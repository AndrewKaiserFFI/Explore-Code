# collector/vmware_api_collector.py
"""
VMware API Collector

Connects to a VCF 9.1 environment's vCenter (and, per-host, ESXi via vCenter)
and pulls the full configuration state needed for drift comparison:
  - vCenter version/build
  - ESXi host versions/builds
  - Networking (vSwitches, portgroups, VMkernel adapters, management network)
  - Storage (datastores, multipathing)
  - Security (lockdown mode, certificates)
  - Time (NTP config, timezone)
  - Logging (syslog forwarding)

Output is a nested dict matching the key structure expected by the
comparison engine's rules_kb.py (e.g. "vcenter.version", "esxi.<host>.version",
"network.management.*", "esxi.network.management_vmk", etc.) after flattening.

Requires: pyVmomi, requests
    pip install pyvmomi requests
"""

import ssl
import atexit
import logging
from typing import Any, Dict, Optional

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

logger = logging.getLogger("vmware_api_collector")
logging.basicConfig(level=logging.INFO)


class VMwareConfigCollector:
    def __init__(
        self,
        vcenter_host: str,
        username: str,
        password: str,
        port: int = 443,
        disable_ssl_verification: bool = True,
    ):
        self.vcenter_host = vcenter_host
        self.username = username
        self.password = password
        self.port = port
        self.disable_ssl_verification = disable_ssl_verification
        self.si = None
        self.content = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    def connect(self):
        logger.info(f"Connecting to vCenter {self.vcenter_host}...")
        context = None
        if self.disable_ssl_verification:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        self.si = SmartConnect(
            host=self.vcenter_host,
            user=self.username,
            pwd=self.password,
            port=self.port,
            sslContext=context,
        )
        atexit.register(Disconnect, self.si)
        self.content = self.si.RetrieveContent()
        logger.info("Connected successfully.")

    def disconnect(self):
        if self.si:
            Disconnect(self.si)
            logger.info("Disconnected from vCenter.")

    # ------------------------------------------------------------------
    # Top-level collection entry point
    # ------------------------------------------------------------------
    def collect_all(self) -> Dict[str, Any]:
        """
        Runs full collection across all categories and returns a single
        nested config dict ready for flattening/comparison.
        """
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

    # ------------------------------------------------------------------
    # vCenter-level configuration
    # ------------------------------------------------------------------
    def _collect_vcenter_config(self) -> Dict[str, Any]:
        about = self.content.about
        vcenter_cfg = {
            "version": about.version,
            "build": about.build,
            "api_version": about.apiVersion,
            "instance_uuid": about.instanceUuid,
            "network": self._collect_vcenter_network_config(),
            "authentication": self._collect_vcenter_auth_config(),
            "certificate": self._collect_vcenter_certificate_info(),
        }
        return vcenter_cfg

    def _collect_vcenter_network_config(self) -> Dict[str, Any]:
        """
        vCenter Server Appliance network settings via the vCenter's own
        managed IP/hostname info exposed through service content.
        (For deeper VAMI-level network config — NICs, static routes — an
        additional call to the VCSA appliance management API would be used;
        stubbed here for extensibility.)
        """
        try:
            server_fqdn = self.content.setting  # placeholder access point
        except Exception:
            server_fqdn = None

        return {
            "managed_ip": getattr(self.si._stub, "host", self.vcenter_host),
            # Extend with VAMI API calls (https://<vcenter>:5480/rest/appliance/networking)
            # for full NIC/DNS/static route detail as needed.
        }

    def _collect_vcenter_auth_config(self) -> Dict[str, Any]:
        """SSO/identity source summary (high level; extend as needed)."""
        try:
            auth_manager = self.content.authorizationManager
            return {
                "description": auth_manager.description.summary if auth_manager else None,
            }
        except Exception as exc:
            logger.warning(f"Could not collect vCenter auth config: {exc}")
            return {}

    def _collect_vcenter_certificate_info(self) -> Dict[str, Any]:
        """
        vCenter machine SSL certificate thumbprint (basic identity check).
        Deeper cert chain detail available via VECS API if needed.
        """
        try:
            return {
                "thumbprint": self.si._stub.soapStub.cookie  # not a real thumbprint;
                # placeholder — replace with a call to the VECS/cert-management
                # API for the actual machine SSL cert thumbprint.
            }
        except Exception as exc:
            logger.warning(f"Could not collect vCenter certificate info: {exc}")
            return {}

    # ------------------------------------------------------------------
    # ESXi host-level configuration
    # ------------------------------------------------------------------
    def _get_all_hosts(self):
        view = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [vim.HostSystem], True
        )
        hosts = list(view.view)
        view.Destroy()
        return hosts

    def _collect_all_hosts_config(self) -> Dict[str, Any]:
        hosts_config: Dict[str, Any] = {}
        for host in self._get_all_hosts():
            host_key = self._sanitize_key(host.name)
            hosts_config[host_key] = self._collect_single_host_config(host)
        return hosts_config

    def _collect_single_host_config(self, host: vim.HostSystem) -> Dict[str, Any]:
        return {
            "version": host.config.product.version if host.config else None,
            "build": host.config.product.build if host.config else None,
            "network": self._collect_host_network_config(host),
            "storage": self._collect_host_storage_config(host),
            "security": self._collect_host_security_config(host),
            "time": self._collect_host_time_config(host),
            "logging": self._collect_host_logging_config(host),
        }

    def _collect_host_network_config(self, host: vim.HostSystem) -> Dict[str, Any]:
        net_cfg = {}
        try:
            network_info = host.config.network

            # vSwitches
            net_cfg["vswitches"] = [
                {"name": vs.name, "num_ports": vs.spec.numPorts}
                for vs in (network_info.vswitch or [])
            ]

            # Port groups
            net_cfg["portgroups"] = [
                {"name": pg.spec.name, "vlan_id": pg.spec.vlanId}
                for pg in (network_info.portgroup or [])
            ]

            # VMkernel adapters — flag the management interface specifically
            vnic_entries = []
            management_vmk = None
            for vnic in (network_info.vnic or []):
                entry = {
                    "device": vnic.device,
                    "ip": vnic.spec.ip.ipAddress if vnic.spec.ip else None,
                    "subnet_mask": vnic.spec.ip.subnetMask if vnic.spec.ip else None,
                    "portgroup": vnic.portgroup,
                }
                vnic_entries.append(entry)

            # Determine which vnic is tagged for management traffic
            vnic_manager = host.configManager.virtualNicManager
            if vnic_manager:
                net_info = vnic_manager.QueryNetConfig("management")
                if net_info and net_info.selectedVnic:
                    management_vmk = net_info.selectedVnic

            net_cfg["vmkernel_adapters"] = vnic_entries
            net_cfg["management_vmk"] = management_vmk

            # DNS config
            dns_cfg = network_info.dnsConfig
            net_cfg["dns"] = {
                "hostname": dns_cfg.hostName if dns_cfg else None,
                "domain": dns_cfg.domainName if dns_cfg else None,
                "servers": list(dns_cfg.address) if dns_cfg and dns_cfg.address else [],
            }

        except Exception as exc:
            logger.warning(f"Could not collect network config for {host.name}: {exc}")

        return net_cfg

    def _collect_host_storage_config(self, host: vim.HostSystem) -> Dict[str, Any]:
        storage_cfg = {}
        try:
            storage_device = host.config.storageDevice
            storage_cfg["multipath_policy"] = [
                {
                    "lun_key": mp.lun,
                    "policy": mp.policy.policy if mp.policy else None,
                }
                for mp in (storage_device.multipathInfo.lun if storage_device and storage_device.multipathInfo else [])
            ]

            storage_cfg["datastores"] = [
                {"name": ds.name}
                for ds in (host.datastore or [])
            ]

            # iSCSI software adapter settings, if present
            iscsi_hbas = [
                hba for hba in (storage_device.hostBusAdapter or [])
                if isinstance(hba, vim.host.InternetScsiHba)
            ] if storage_device else []
            storage_cfg["iscsi"] = [
                {"iqn": hba.iScsiName, "enabled": hba.authenticationProperties is not None}
                for hba in iscsi_hbas
            ]

        except Exception as exc:
            logger.warning(f"Could not collect storage config for {host.name}: {exc}")

        return storage_cfg

    def _collect_host_security_config(self, host: vim.HostSystem) -> Dict[str, Any]:
        sec_cfg = {}
        try:
            sec_cfg["lockdown_mode"] = str(host.config.lockdownMode) if host.config else None

            # Host certificate info (thumbprint) - useful to detect cert drift
            cert_info = getattr(host.config, "certificate", None)
            sec_cfg["certificate_thumbprint"] = (
                cert_info.hex() if isinstance(cert_info, (bytes, bytearray)) else None
            )

            # Firewall / management access ruleset summary
            firewall_info = host.configManager.firewallSystem.firewallInfo if host.configManager.firewallSystem else None
            sec_cfg["firewall_management_rules"] = [
                {"rule": rs.ruleset.key, "enabled": rs.enabled}
                for rs in (firewall_info.ruleset if firewall_info else [])
                if "management" in rs.ruleset.key.lower()
            ]

        except Exception as exc:
            logger.warning(f"Could not collect security config for {host.name}: {exc}")

        return sec_cfg

    def _collect_host_time_config(self, host: vim.HostSystem) -> Dict[str, Any]:
        time_cfg = {}
        try:
            date_time_info = host.config.dateTimeInfo
            ntp_config = date_time_info.ntpConfig if date_time_info else None
            time_cfg["ntp"] = {
                "servers": list(ntp_config.server) if ntp_config and ntp_config.server else [],
            }
            time_cfg["timezone"] = (
                date_time_info.timeZone.name if date_time_info and date_time_info.timeZone else None
            )
        except Exception as exc:
            logger.warning(f"Could not collect time config for {host.name}: {exc}")

        return time_cfg

    def _collect_host_logging_config(self, host: vim.HostSystem) -> Dict[str, Any]:
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

    # ------------------------------------------------------------------
    # Global (cluster/datacenter-wide) summaries
    # ------------------------------------------------------------------
    def _collect_global_network_config(self) -> Dict[str, Any]:
        """
        Placeholder for datacenter-wide distributed switch / management
        network settings that apply above the individual host level
        (e.g. vDS uplinks, NSX transport zones if applicable).
        """
        global_net = {"management": {}}
        try:
            view = self.content.viewManager.CreateContainerView(
                self.content.rootFolder, [vim.DistributedVirtualSwitch], True
            )
            dvswitches = list(view.view)
            view.Destroy()

            global_net["distributed_switches"] = [
                {"name": dvs.name, "uuid": dvs.uuid} for dvs in dvswitches
            ]
        except Exception as exc:
            logger.warning(f"Could not collect global network config: {exc}")

        return global_net

    def _collect_global_storage_summary(self) -> Dict[str, Any]:
        return {}  # extend as needed (e.g. VMFS versions cluster-wide, VSAN policies)

    def _collect_global_security_config(self) -> Dict[str, Any]:
        return {}  # extend as needed (e.g. SSO password policy, cluster-wide firewall rules)

    def _collect_global_time_summary(self) -> Dict[str, Any]:
        return {}  # per-host time already captured; extend for vCenter-level NTP if applicable

    def _collect_global_logging_summary(self) -> Dict[str, Any]:
        return {}  # extend for vCenter-level log forwarding (vRLI, syslog) config

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _sanitize_key(name: str) -> str:
        """Make host/object names safe as dotted-path config keys."""
        return name.replace(".", "_").replace(" ", "_")