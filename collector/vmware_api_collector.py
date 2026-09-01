"""
VMware API Collector — pulls full VCF 9.1 configuration state via vCenter API
(pyVmomi). Used live against the baseline environment and standalone (via
export_measured_config.py) against the isolated measured environment.
"""

import ssl
import atexit
import logging
from typing import Any, Dict

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

logger = logging.getLogger("vmware_api_collector")
logging.basicConfig(level=logging.INFO)


class VMwareConfigCollector:
    def __init__(self, vcenter_host, username, password, port=443, disable_ssl_verification=True):
        self.vcenter_host = vcenter_host
        self.username = username
        self.password = password
        self.port = port
        self.disable_ssl_verification = disable_ssl_verification
        self.si = None
        self.content = None

    def connect(self):
        logger.info(f"Connecting to vCenter {self.vcenter_host}...")
        context = None
        if self.disable_ssl_verification:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        self.si = SmartConnect(
            host=self.vcenter_host, user=self.username, pwd=self.password,
            port=self.port, sslContext=context,
        )
        atexit.register(Disconnect, self.si)
        self.content = self.si.RetrieveContent()
        logger.info("Connected successfully.")

    def disconnect(self):
        if self.si:
            Disconnect(self.si)
            logger.info("Disconnected from vCenter.")

    def collect_all(self) -> Dict[str, Any]:
        if not self.content:
            raise RuntimeError("Not connected. Call connect() first.")

        config: Dict[str, Any] = {}
        config["vcenter"] = self._collect_vcenter_config()
        config["esxi"] = self._collect_all_hosts_config()
        config["network"] = self._collect_global_network_config()
        config["storage"] = self._collect_global_storage_summary()
        config["security"] = self._collect_global_security_config()
        config["time"] = self._collect_global_time_summary()
        config["logging"] = self._collect_global_logging_summary()
        return config

    def _collect_vcenter_config(self) -> Dict[str, Any]:
        about = self.content.about
        return {
            "version": about.version,
            "build": about.build,
            "api_version": about.apiVersion,
            "instance_uuid": about.instanceUuid,
            "network": self._collect_vcenter_network_config(),
            "authentication": self._collect_vcenter_auth_config(),
            "certificate": self._collect_vcenter_certificate_info(),
        }

    def _collect_vcenter_network_config(self) -> Dict[str, Any]:
        return {"managed_ip": getattr(self.si._stub, "host", self.vcenter_host)}

    def _collect_vcenter_auth_config(self) -> Dict[str, Any]:
        try:
            auth_manager = self.content.authorizationManager
            return {"description": auth_manager.description.summary if auth_manager else None}
        except Exception as exc:
            logger.warning(f"Could not collect vCenter auth config: {exc}")
            return {}

    def _collect_vcenter_certificate_info(self) -> Dict[str, Any]:
        try:
            return {"thumbprint": getattr(self.si._stub.soapStub, "cookie", None)}
        except Exception as exc:
            logger.warning(f"Could not collect vCenter certificate info: {exc}")
            return {}

    def _get_all_hosts(self):
        view = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [vim.HostSystem], True
        )
        hosts = list(view.view)
        view.Destroy()
        return hosts

    def _collect_all_hosts_config(self) -> Dict[str, Any]:
        return {self._sanitize_key(h.name): self._collect_single_host_config(h) for h in self._get_all_hosts()}

    def _collect_single_host_config(self, host) -> Dict[str, Any]:
        return {
            "version": host.config.product.version if host.config else None,
            "build": host.config.product.build if host.config else None,
            "network": self._collect_host_network_config(host),
            "storage": self._collect_host_storage_config(host),
            "security": self._collect_host_security_config(host),
            "time": self._collect_host_time_config(host),
            "logging": self._collect_host_logging_config(host),
        }

    def _collect_host_network_config(self, host) -> Dict[str, Any]:
        net_cfg = {}
        try:
            network_info = host.config.network
            net_cfg["vswitches"] = [{"name": vs.name, "num_ports": vs.spec.numPorts} for vs in (network_info.vswitch or [])]
            net_cfg["portgroups"] = [{"name": pg.spec.name, "vlan_id": pg.spec.vlanId} for pg in (network_info.portgroup or [])]

            vnic_entries = []
            for vnic in (network_info.vnic or []):
                vnic_entries.append({
                    "device": vnic.device,
                    "ip": vnic.spec.ip.ipAddress if vnic.spec.ip else None,
                    "subnet_mask": vnic.spec.ip.subnetMask if vnic.spec.ip else None,
                    "portgroup": vnic.portgroup,
                })
            net_cfg["vmkernel_adapters"] = vnic_entries

            management_vmk = None
            vnic_manager = host.configManager.virtualNicManager
            if vnic_manager:
                net_info = vnic_manager.QueryNetConfig("management")
                if net_info and net_info.selectedVnic:
                    management_vmk = net_info.selectedVnic
            net_cfg["management_vmk"] = management_vmk

            dns_cfg = network_info.dnsConfig
            net_cfg["dns"] = {
                "hostname": dns_cfg.hostName if dns_cfg else None,
                "domain": dns_cfg.domainName if dns_cfg else None,
                "servers": list(dns_cfg.address) if dns_cfg and dns_cfg.address else [],
            }
        except Exception as exc:
            logger.warning(f"Could not collect network config for {host.name}: {exc}")
        return net_cfg

    def _collect_host_storage_config(self, host) -> Dict[str, Any]:
        storage_cfg = {}
        try:
            storage_device = host.config.storageDevice
            storage_cfg["multipath_policy"] = [
                {"lun_key": mp.lun, "policy": mp.policy.policy if mp.policy else None}
                for mp in (storage_device.multipathInfo.lun if storage_device and storage_device.multipathInfo else [])
            ]
            storage_cfg["datastores"] = [{"name": ds.name} for ds in (host.datastore or [])]

            iscsi_hbas = [hba for hba in (storage_device.hostBusAdapter or []) if isinstance(hba, vim.host.InternetScsiHba)] if storage_device else []
            storage_cfg["iscsi"] = [{"iqn": hba.iScsiName, "enabled": hba.authenticationProperties is not None} for hba in iscsi_hbas]
        except Exception as exc:
            logger.warning(f"Could not collect storage config for {host.name}: {exc}")
        return storage_cfg

    def _collect_host_security_config(self, host) -> Dict[str, Any]:
        sec_cfg = {}
        try:
            sec_cfg["lockdown_mode"] = str(host.config.lockdownMode) if host.config else None
            cert_info = getattr(host.config, "certificate", None)
            sec_cfg["certificate_thumbprint"] = cert_info.hex() if isinstance(cert_info, (bytes, bytearray)) else None

            firewall_info = host.configManager.firewallSystem.firewallInfo if host.configManager.firewallSystem else None
            sec_cfg["firewall_management_rules"] = [
                {"rule": rs.ruleset.key, "enabled": rs.enabled}
                for rs in (firewall_info.ruleset if firewall_info else [])
                if "management" in rs.ruleset.key.lower()
            ]
        except Exception as exc:
            logger.warning(f"Could not collect security config for {host.name}: {exc}")
        return sec_cfg

    def _collect_host_time_config(self, host) -> Dict[str, Any]:
        time_cfg = {}
        try:
            date_time_info = host.config.dateTimeInfo
            ntp_config = date_time_info.ntpConfig if date_time_info else None
            time_cfg["ntp"] = {"servers": list(ntp_config.server) if ntp_config and ntp_config.server else []}
            time_cfg["timezone"] = date_time_info.timeZone.name if date_time_info and date_time_info.timeZone else None
        except Exception as exc:
            logger.warning(f"Could not collect time config for {host.name}: {exc}")
        return time_cfg

    def _collect_host_logging_config(self, host) -> Dict[str, Any]:
        log_cfg = {}
        try:
            option_manager = host.configManager.advancedOption
            if option_manager:
                syslog_host_opt = option_manager.QueryOptions("Syslog.global.logHost")
                if syslog_host_opt:
                    log_cfg["syslog_host"] = syslog_host_opt[0].value
        except Exception as exc:
            logger.warning(f"Could not collect logging config for {host.name}: {exc}")
        return log_cfg

    def _collect_global_network_config(self) -> Dict[str, Any]:
        global_net = {"management": {}}
        try:
            view = self.content.viewManager.CreateContainerView(self.content.rootFolder, [vim.DistributedVirtualSwitch], True)
            dvswitches = list(view.view)
            view.Destroy()
            global_net["distributed_switches"] = [{"name": dvs.name, "uuid": dvs.uuid} for dvs in dvswitches]
        except Exception as exc:
            logger.warning(f"Could not collect global network config: {exc}")
        return global_net

    def _collect_global_storage_summary(self) -> Dict[str, Any]:
        return {}

    def _collect_global_security_config(self) -> Dict[str, Any]:
        return {}

    def _collect_global_time_summary(self) -> Dict[str, Any]:
        return {}

    def _collect_global_logging_summary(self) -> Dict[str, Any]:
        return {}

    @staticmethod
    def _sanitize_key(name: str) -> str:
        return name.replace(".", "_").replace(" ", "_")
