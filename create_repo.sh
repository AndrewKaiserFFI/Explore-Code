touch auth/__init__.py

cat <<'FILEEOF' > auth/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp

from models_auth import User


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[
        DataRequired(), Length(min=3, max=64),
        Regexp(r"^[A-Za-z0-9_.-]+$", message="Letters, numbers, '.', '_', '-' only."),
    ])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[
        DataRequired(), Length(min=10, message="Minimum 10 characters."),
    ])
    confirm_password = PasswordField("Confirm Password", validators=[
        DataRequired(), EqualTo("password", message="Passwords must match."),
    ])
    submit = SubmitField("Create Account")

    def validate_username(self, field):
        from db import db_session
        if db_session.query(User).filter_by(username=field.data).first():
            raise ValidationError("That username is already taken.")

    def validate_email(self, field):
        from db import db_session
        if db_session.query(User).filter_by(email=field.data.lower()).first():
            raise ValidationError("An account with that email already exists.")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")
FILEEOF

cat <<'FILEEOF' > auth/decorators.py
from functools import wraps
from flask import abort
from flask_login import login_required, current_user

__all__ = ["login_required", "admin_required"]


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated
FILEEOF

cat <<'FILEEOF' > auth/routes.py
import logging
from datetime import datetime

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from db import db_session
from models_auth import User, UserRole
from auth.forms import RegistrationForm, LoginForm
from extensions import bcrypt, login_manager

logger = logging.getLogger("auth")
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@login_manager.user_loader
def load_user(user_id):
    return db_session.query(User).get(int(user_id))


@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("reports.dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        password_hash = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user_count = db_session.query(User).count()
        role = UserRole.ADMIN if user_count == 0 else UserRole.VIEWER

        new_user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            password_hash=password_hash,
            role=role,
        )
        db_session.add(new_user)
        db_session.commit()

        logger.info(f"New user registered: {new_user.username} (role={role})")
        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/signup.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("reports.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = db_session.query(User).filter_by(username=form.username.data.strip()).first()

        if user is None or not bcrypt.check_password_hash(user.password_hash, form.password.data):
            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html", form=form)

        if not user.is_active_account:
            flash("This account has been disabled. Contact an administrator.", "danger")
            return render_template("auth/login.html", form=form)

        login_user(user)
        user.last_login_at = datetime.utcnow()
        db_session.commit()
        logger.info(f"User logged in: {user.username}")

        next_page = request.args.get("next")
        return redirect(next_page or url_for("reports.dashboard"))

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logger.info(f"User logged out: {current_user.username}")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
FILEEOF

# ----------------------------------------------------------------------
# reports/
# ----------------------------------------------------------------------

touch reports/__init__.py

cat <<'FILEEOF' > reports/ingestion.py
"""
Handles:
  - Live baseline capture (calls VMwareConfigCollector directly).
  - Git-based ingestion of measured-environment export packages
    (produced by collector/export_measured_config.py in the isolated
    measured environment and pushed to a Git repo).
"""

import os
import json
import zipfile
import logging
import subprocess
from datetime import datetime

from models import Snapshot, EnvironmentRole
from comparison_engine import ComparisonEngine

logger = logging.getLogger("ingestion")

GIT_REPO_DIR = os.environ.get("GIT_REPO_DIR", "/opt/vcf-drift-app/git_repo")


def get_latest_snapshot(db_session, role: EnvironmentRole):
    return (
        db_session.query(Snapshot)
        .filter(Snapshot.role == role)
        .order_by(Snapshot.captured_at.desc())
        .first()
    )


def capture_baseline_live(db_session, environment_name: str) -> Snapshot:
    """
    Connects directly to the baseline environment via the VMware API
    collector and stores a new baseline Snapshot.
    """
    from collector.vmware_api_collector import VMwareConfigCollector

    host = os.environ["BASELINE_VCENTER_HOST"]
    user = os.environ["BASELINE_VCENTER_USER"]
    password = os.environ["BASELINE_VCENTER_PASSWORD"]

    collector = VMwareConfigCollector(vcenter_host=host, username=user, password=password)
    try:
        collector.connect()
        config = collector.collect_all()
    finally:
        collector.disconnect()

    snapshot = Snapshot(
        role=EnvironmentRole.BASELINE,
        environment_name=environment_name,
        captured_at=datetime.utcnow(),
        source="vmware_api_collector_live",
        raw_config=config,
    )
    db_session.add(snapshot)
    db_session.commit()

    logger.info(f"Captured new baseline snapshot id={snapshot.id}")

    latest_measured = get_latest_snapshot(db_session, EnvironmentRole.MEASURED)
    if latest_measured:
        ComparisonEngine(db_session).compare(snapshot, latest_measured)

    return snapshot


def pull_git_repo():
    if not os.path.isdir(os.path.join(GIT_REPO_DIR, ".git")):
        raise RuntimeError(f"{GIT_REPO_DIR} is not a valid git repository.")
    subprocess.run(["git", "-C", GIT_REPO_DIR, "pull"], check=True)
    logger.info(f"Pulled latest changes into {GIT_REPO_DIR}")


def sync_measured_exports_from_git(db_session, environment_name: str):
    """
    Pulls the Git repo, scans exports/<environment_name>/ for zip packages
    not yet ingested, ingests each new one as a measured Snapshot, then
    triggers remediation status recalculation against the latest baseline.
    """
    pull_git_repo()

    exports_dir = os.path.join(GIT_REPO_DIR, "exports", environment_name)
    if not os.path.isdir(exports_dir):
        logger.warning(f"No exports directory found at {exports_dir}")
        return []

    already_ingested_sources = {
        row[0] for row in db_session.query(Snapshot.source)
        .filter(Snapshot.role == EnvironmentRole.MEASURED)
        .all()
    }

    new_snapshots = []
    zip_files = sorted(f for f in os.listdir(exports_dir) if f.endswith(".zip"))

    for zip_filename in zip_files:
        if zip_filename in already_ingested_sources:
            continue

        zip_path = os.path.join(exports_dir, zip_filename)
        snapshot = _ingest_zip_package(db_session, zip_path, zip_filename, environment_name)
        new_snapshots.append(snapshot)

    baseline = get_latest_snapshot(db_session, EnvironmentRole.BASELINE)
    if baseline and new_snapshots:
        engine = ComparisonEngine(db_session)
        for snapshot in new_snapshots:
            engine.recalculate_remediation_status(baseline, snapshot)

    return new_snapshots


def _ingest_zip_package(db_session, zip_path: str, zip_filename: str, environment_name: str) -> Snapshot:
    extract_dir = zip_path + "_extracted"
    os.makedirs(extract_dir, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zipf:
        zipf.extractall(extract_dir)

    config_path = os.path.join(extract_dir, "config.json")
    metadata_path = os.path.join(extract_dir, "metadata.json")

    with open(config_path) as f:
        config = json.load(f)

    captured_at = datetime.utcnow()
    if os.path.exists(metadata_path):
        with open(metadata_path) as f:
            metadata = json.load(f)
        try:
            captured_at = datetime.strptime(metadata["captured_at_utc"], "%Y%m%dT%H%M%SZ")
        except Exception:
            pass

    snapshot = Snapshot(
        role=EnvironmentRole.MEASURED,
        environment_name=environment_name,
        captured_at=captured_at,
        source=zip_filename,
        raw_config=config,
    )
    db_session.add(snapshot)
    db_session.commit()

    logger.info(f"Ingested measured snapshot id={snapshot.id} from {zip_filename}")
    return snapshot
FILEEOF

cat <<'FILEEOF' > reports/routes.py
"""
Report views: dashboard, detailed drift lists (by category), remediation
plan (grouped by outage requirement), breaking changes, remediation history.
All routes require login.
"""

import os
from flask import Blueprint, render_template, request, redirect, url_for, flash

from db import db_session
from auth.decorators import login_required, admin_required
from models import Snapshot, DriftFinding, EnvironmentRole, FindingStatus, Category
from reports.ingestion import capture_baseline_live, sync_measured_exports_from_git, get_latest_snapshot

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


def _latest_pair():
    baseline = get_latest_snapshot(db_session, EnvironmentRole.BASELINE)
    measured = get_latest_snapshot(db_session, EnvironmentRole.MEASURED)
    return baseline, measured


def _current_findings_query():
    baseline, measured = _latest_pair()
    if not baseline or not measured:
        return None, None, None
    query = db_session.query(DriftFinding).filter(
        DriftFinding.baseline_snapshot_id == baseline.id,
        DriftFinding.measured_snapshot_id == measured.id,
    )
    return query, baseline, measured


@reports_bp.route("/")
@login_required
def dashboard():
    baseline, measured = _latest_pair()

    version_alert = None
    if baseline and measured:
        b_vc = baseline.raw_config.get("vcenter", {}).get("version")
        m_vc = measured.raw_config.get("vcenter", {}).get("version")
        if b_vc and m_vc and b_vc != m_vc:
            version_alert = f"vCenter version mismatch: baseline={b_vc}, measured={m_vc}"

    query, _, _ = _current_findings_query()
    summary = {"total": 0, "breaking": 0, "requires_outage": 0, "open": 0}
    if query is not None:
        all_findings = query.all()
        summary["total"] = len(all_findings)
        summary["breaking"] = sum(1 for f in all_findings if f.is_breaking_change)
        summary["requires_outage"] = sum(1 for f in all_findings if f.requires_outage)
        summary["open"] = sum(1 for f in all_findings if f.status == FindingStatus.OPEN)

    return render_template(
        "reports/dashboard.html",
        baseline=baseline,
        measured=measured,
        version_alert=version_alert,
        summary=summary,
    )


@reports_bp.route("/capture-baseline", methods=["POST"])
@admin_required
def capture_baseline():
    environment_name = os.environ.get("BASELINE_ENVIRONMENT_NAME", "baseline")
    try:
        capture_baseline_live(db_session, environment_name)
        flash("Baseline captured and compared successfully.", "success")
    except Exception as exc:
        flash(f"Failed to capture baseline: {exc}", "danger")
    return redirect(url_for("reports.dashboard"))


@reports_bp.route("/sync-measured", methods=["POST"])
@admin_required
def sync_measured():
    environment_name = os.environ.get("MEASURED_ENVIRONMENT_NAME", "measured")
    try:
        new_snapshots = sync_measured_exports_from_git(db_session, environment_name)
        flash(f"Synced {len(new_snapshots)} new measured snapshot(s) from Git.", "success")
    except Exception as exc:
        flash(f"Failed to sync measured exports: {exc}", "danger")
    return redirect(url_for("reports.dashboard"))


@reports_bp.route("/drift")
@login_required
def drift_list():
    query, baseline, measured = _current_findings_query()
    category_filter = request.args.get("category")

    findings = []
    if query is not None:
        if category_filter:
            query = query.filter(DriftFinding.category == category_filter)
        findings = query.order_by(DriftFinding.category, DriftFinding.setting_key).all()

    return render_template(
        "reports/drift_list.html",
        findings=findings,
        baseline=baseline,
        measured=measured,
        categories=[c.value for c in Category],
        selected_category=category_filter,
    )


@reports_bp.route("/remediation-plan")
@login_required
def remediation_plan():
    query, baseline, measured = _current_findings_query()

    outage_required = []
    live_remediable = []
    if query is not None:
        open_findings = query.filter(DriftFinding.status == FindingStatus.OPEN).all()
        outage_required = [f for f in open_findings if f.requires_outage]
        live_remediable = [f for f in open_findings if not f.requires_outage]

    return render_template(
        "reports/remediation_plan.html",
        outage_required=outage_required,
        live_remediable=live_remediable,
        baseline=baseline,
        measured=measured,
    )


@reports_bp.route("/breaking-changes")
@login_required
def breaking_changes():
    query, baseline, measured = _current_findings_query()

    findings = []
    if query is not None:
        findings = (
            query.filter(
                DriftFinding.is_breaking_change == True,  # noqa: E712
                DriftFinding.status == FindingStatus.OPEN,
            )
            .order_by(DriftFinding.impacts_management_network.desc(), DriftFinding.category)
            .all()
        )

    return render_template(
        "reports/breaking_changes.html",
        findings=findings,
        baseline=baseline,
        measured=measured,
    )


@reports_bp.route("/remediation-history")
@login_required
def remediation_history():
    baseline = get_latest_snapshot(db_session, EnvironmentRole.BASELINE)

    findings = []
    if baseline:
        findings = (
            db_session.query(DriftFinding)
            .filter(DriftFinding.baseline_snapshot_id == baseline.id)
            .order_by(DriftFinding.first_detected_at.desc())
            .all()
        )

    return render_template(
        "reports/remediation_history.html",
        findings=findings,
        baseline=baseline,
    )
FILEEOF

# ----------------------------------------------------------------------
# backup/
# ----------------------------------------------------------------------

touch backup/__init__.py

cat <<'FILEEOF' > backup/routes.py
"""
Web-exposed backup controls. Restore is CLI-only (deploy/restore_db.sh)
since it requires stopping the app service — this blueprint only
lists/triggers/downloads backups.
"""

import os
import subprocess
from flask import Blueprint, render_template, send_from_directory, flash, redirect, url_for

from auth.decorators import admin_required

backup_bp = Blueprint("backup", __name__, url_prefix="/backup")

APP_DIR = os.environ.get("APP_DIR", "/opt/vcf-drift-app")
BACKUP_DIR = os.environ.get("BACKUP_DIR", os.path.join(APP_DIR, "backups"))
BACKUP_SCRIPT = os.path.join(APP_DIR, "backup_db.sh")


@backup_bp.route("/")
@admin_required
def list_backups():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    files = sorted(
        (f for f in os.listdir(BACKUP_DIR) if f.endswith(".sql.gz")),
        reverse=True,
    )
    return render_template("backup/backup.html", files=files)


@backup_bp.route("/run", methods=["POST"])
@admin_required
def run_backup():
    try:
        subprocess.run(["bash", BACKUP_SCRIPT], check=True)
        flash("Backup completed successfully.", "success")
    except Exception as exc:
        flash(f"Backup failed: {exc}", "danger")
    return redirect(url_for("backup.list_backups"))


@backup_bp.route("/download/<path:filename>")
@admin_required
def download_backup(filename):
    return send_from_directory(BACKUP_DIR, filename, as_attachment=True)
FILEEOF

# ----------------------------------------------------------------------
# collector/
# ----------------------------------------------------------------------

cat <<'FILEEOF' > collector/vmware_api_collector.py
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
FILEEOF

cat <<'FILEEOF' > collector/export_measured_config.py
"""
Standalone export utility — run inside/against the isolated MEASURED
environment. Collects config via VMwareConfigCollector, packages it, and
optionally pushes it to Git for later ingestion by the web app.
"""

import os
import json
import shutil
import zipfile
import argparse
import subprocess
import logging
from datetime import datetime, timezone

from vmware_api_collector import VMwareConfigCollector

logger = logging.getLogger("export_measured_config")
logging.basicConfig(level=logging.INFO)


def get_required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise EnvironmentError(f"Required environment variable '{name}' is not set.")
    return value


def package_export(config: dict, environment_name: str, output_root: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    package_name = f"{environment_name}_{timestamp}"
    package_dir = os.path.join(output_root, package_name)
    os.makedirs(package_dir, exist_ok=True)

    with open(os.path.join(package_dir, "config.json"), "w") as f:
        json.dump(config, f, indent=2, default=str)

    metadata = {
        "environment_name": environment_name,
        "captured_at_utc": timestamp,
        "role": "measured",
        "collector_version": "1.0",
    }
    with open(os.path.join(package_dir, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    zip_path = os.path.join(output_root, f"{package_name}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(package_dir):
            for file in files:
                file_path = os.path.join(root, file)
                zipf.write(file_path, os.path.relpath(file_path, package_dir))

    logger.info(f"Packaged export at: {zip_path}")
    return zip_path


def push_to_git(git_repo_dir: str, package_path: str, environment_name: str):
    if not os.path.isdir(os.path.join(git_repo_dir, ".git")):
        raise RuntimeError(f"{git_repo_dir} is not a valid git repository.")

    dest_dir = os.path.join(git_repo_dir, "exports", environment_name)
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, os.path.basename(package_path))
    shutil.copy2(package_path, dest_path)

    commit_message = f"Add measured config export: {os.path.basename(package_path)}"
    subprocess.run(["git", "-C", git_repo_dir, "add", dest_path], check=True)
    subprocess.run(["git", "-C", git_repo_dir, "commit", "-m", commit_message], check=True)
    subprocess.run(["git", "-C", git_repo_dir, "push"], check=True)

    logger.info(f"Pushed export to Git repo: {dest_path}")


def main():
    parser = argparse.ArgumentParser(description="Export measured VCF environment config.")
    parser.add_argument("--output-dir", default="./exports")
    parser.add_argument("--push-to-git", action="store_true")
    args = parser.parse_args()

    vcenter_host = get_required_env("VCENTER_HOST")
    vcenter_user = get_required_env("VCENTER_USER")
    vcenter_password = get_required_env("VCENTER_PASSWORD")
    environment_name = os.environ.get("ENVIRONMENT_NAME", "measured")

    os.makedirs(args.output_dir, exist_ok=True)

    collector = VMwareConfigCollector(vcenter_host=vcenter_host, username=vcenter_user, password=vcenter_password)
    try:
        collector.connect()
        config = collector.collect_all()
    finally:
        collector.disconnect()

    package_path = package_export(config, environment_name, args.output_dir)

    if args.push_to_git:
        git_repo_dir = get_required_env("GIT_REPO_DIR")
        push_to_git(git_repo_dir, package_path, environment_name)

    logger.info("Export complete.")


if __name__ == "__main__":
    main()
FILEEOF

cat <<'FILEEOF' > collector/requirements.txt
pyvmomi==8.0.3.0.1
requests==2.32.3
FILEEOF

# ----------------------------------------------------------------------
# templates/
# ----------------------------------------------------------------------

cat <<'FILEEOF' > templates/base.html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VCF Config Drift Comparison</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; background: #f4f5f7; }
    nav { background: #1b2a4a; padding: 12px 20px; }
    nav a { color: #fff; margin-right: 16px; text-decoration: none; }
    .container { padding: 20px; max-width: 1100px; margin: auto; }
    table { border-collapse: collapse; width: 100%; background: #fff; margin-top: 12px; }
    th, td { border: 1px solid #ddd; padding: 8px; font-size: 14px; text-align: left; }
    th { background: #eef1f7; }
    .badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; color: #fff; }
    .badge-breaking { background: #c0392b; }
    .badge-outage { background: #d68910; }
    .badge-mgmt { background: #6c3483; }
    .badge-open { background: #b03a2e; }
    .badge-resolved { background: #1e8449; }
    .flash { padding: 10px; margin-bottom: 10px; border-radius: 4px; }
    .flash-success { background: #d4efdf; }
    .flash-danger { background: #fadbd8; }
    .flash-info { background: #d6eaf8; }
    .card { background: #fff; padding: 16px; border-radius: 6px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    form.inline { display: inline; }
  </style>
</head>
<body>
  <nav>
    <a href="{{ url_for('reports.dashboard') }}">Dashboard</a>
    <a href="{{ url_for('reports.drift_list') }}">Drift Detail</a>
    <a href="{{ url_for('reports.remediation_plan') }}">Remediation Plan</a>
    <a href="{{ url_for('reports.breaking_changes') }}">Breaking Changes</a>
    <a href="{{ url_for('reports.remediation_history') }}">Remediation History</a>
    <a href="{{ url_for('backup.list_backups') }}">Backups</a>
    {% if current_user.is_authenticated %}
      <a href="{{ url_for('auth.logout') }}" style="float:right;">Log out ({{ current_user.username }})</a>
    {% endif %}
  </nav>
  <div class="container">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}
        <div class="flash flash-{{ category }}">{{ message }}</div>
      {% endfor %}
    {% endwith %}
    {% block content %}{% endblock %}
  </div>
</body>
</html>
FILEEOF

cat <<'FILEEOF' > templates/auth/signup.html
{% extends "base.html" %}
{% block content %}
<h2>Create an Account</h2>
<form method="POST" novalidate>
  {{ form.hidden_tag() }}
  <p>{{ form.username.label }} {{ form.username(size=32) }}
    {% for e in form.username.errors %}<br><span style="color:red">{{ e }}</span>{% endfor %}</p>
  <p>{{ form.email.label }} {{ form.email(size=32) }}
    {% for e in form.email.errors %}<br><span style="color:red">{{ e }}</span>{% endfor %}</p>
  <p>{{ form.password.label }} {{ form.password(size=32) }}
    {% for e in form.password.errors %}<br><span style="color:red">{{ e }}</span>{% endfor %}</p>
  <p>{{ form.confirm_password.label }} {{ form.confirm_password(size=32) }}
    {% for e in form.confirm_password.errors %}<br><span style="color:red">{{ e }}</span>{% endfor %}</p>
  {{ form.submit() }}
</form>
<p>Already have an account? <a href="{{ url_for('auth.login') }}">Log in</a></p>
{% endblock %}
FILEEOF

cat <<'FILEEOF' > templates/auth/login.html
{% extends "base.html" %}
{% block content %}
<h2>Log In</h2>
<form method="POST" novalidate>
  {{ form.hidden_tag() }}
  <p>{{ form.username.label }} {{ form.username(size=32) }}</p>
  <p>{{ form.password.label }} {{ form.password(size=32) }}</p>
  {{ form.submit() }}
</form>
<p>Need an account? <a href="{{ url_for('auth.signup') }}">Sign up</a></p>
{% endblock %}
FILEEOF

cat <<'FILEEOF' > templates/reports/dashboard.html
{% extends "base.html" %}
{% block content %}
<h2>Drift Comparison Dashboard</h2>

{% if version_alert %}
  <div class="card" style="border-left: 5px solid #c0392b;">
    <strong>Warning - Version Mismatch:</strong> {{ version_alert }}
  </div>
{% endif %}

<div class="card">
  <h3>Environments</h3>
  <p><strong>Baseline:</strong>
    {% if baseline %}{{ baseline.environment_name }} (captured {{ baseline.captured_at }}){% else %}Not captured yet{% endif %}
  </p>
  <p><strong>Measured:</strong>
    {% if measured %}{{ measured.environment_name }} (captured {{ measured.captured_at }}, source: {{ measured.source }}){% else %}Not ingested yet{% endif %}
  </p>

  {% if current_user.is_admin() %}
  <form class="inline" method="POST" action="{{ url_for('reports.capture_baseline') }}">
    <button type="submit">Capture Baseline Now (Live API)</button>
  </form>
  <form class="inline" method="POST" action="{{ url_for('reports.sync_measured') }}">
    <button type="submit">Sync Measured Export from Git</button>
  </form>
  {% endif %}
</div>

<div class="card">
  <h3>Summary</h3>
  <ul>
    <li>Total drift findings: {{ summary.total }}</li>
    <li>Open findings: {{ summary.open }}</li>
    <li>Breaking changes: {{ summary.breaking }}</li>
    <li>Requires outage window: {{ summary.requires_outage }}</li>
  </ul>
</div>
{% endblock %}
FILEEOF

cat <<'FILEEOF' > templates/reports/drift_list.html
{% extends "base.html" %}
{% block content %}
<h2>Detailed Drift List</h2>

<form method="GET">
  <label>Category:</label>
  <select name="category" onchange="this.form.submit()">
    <option value="">All</option>
    {% for cat in categories %}
      <option value="{{ cat }}" {% if cat == selected_category %}selected{% endif %}>{{ cat }}</option>
    {% endfor %}
  </select>
</form>

<table>
  <tr>
    <th>Category</th><th>Setting</th><th>Baseline Value</th><th>Measured Value</th>
    <th>Status</th><th>Flags</th>
  </tr>
  {% for f in findings %}
  <tr>
    <td>{{ f.category.value }}</td>
    <td>{{ f.setting_key }}</td>
    <td>{{ f.baseline_value }}</td>
    <td>{{ f.measured_value }}</td>
    <td><span class="badge badge-{{ 'open' if f.status.value == 'open' else 'resolved' }}">{{ f.status.value }}</span></td>
    <td>
      {% if f.is_breaking_change %}<span class="badge badge-breaking">breaking</span>{% endif %}
      {% if f.requires_outage %}<span class="badge badge-outage">outage</span>{% endif %}
      {% if f.impacts_management_network %}<span class="badge badge-mgmt">mgmt-net</span>{% endif %}
    </td>
  </tr>
  {% else %}
  <tr><td colspan="6">No drift findings to display.</td></tr>
  {% endfor %}
</table>
{% endblock %}
FILEEOF

cat <<'FILEEOF' > templates/reports/remediation_plan.html
{% extends "base.html" %}
{% block content %}
<h2>Remediation Plan</h2>

<div class="card">
  <h3>Requires Scheduled Outage Window ({{ outage_required|length }})</h3>
  <table>
    <tr><th>Category</th><th>Setting</th><th>Baseline</th><th>Measured</th><th>Breaking?</th></tr>
    {% for f in outage_required %}
    <tr>
      <td>{{ f.category.value }}</td><td>{{ f.setting_key }}</td>
      <td>{{ f.baseline_value }}</td><td>{{ f.measured_value }}</td>
      <td>{{ "Yes" if f.is_breaking_change else "No" }}</td>
    </tr>
    {% else %}<tr><td colspan="5">None.</td></tr>{% endfor %}
  </table>
</div>

<div class="card">
  <h3>Can Be Remediated Live ({{ live_remediable|length }})</h3>
  <table>
    <tr><th>Category</th><th>Setting</th><th>Baseline</th><th>Measured</th></tr>
    {% for f in live_remediable %}
    <tr>
      <td>{{ f.category.value }}</td><td>{{ f.setting_key }}</td>
      <td>{{ f.baseline_value }}</td><td>{{ f.measured_value }}</td>
    </tr>
    {% else %}<tr><td colspan="4">None.</td></tr>{% endfor %}
  </table>
</div>
{% endblock %}
FILEEOF

cat <<'FILEEOF' > templates/reports/breaking_changes.html
{% extends "base.html" %}
{% block content %}
<h2>Breaking Changes</h2>
<p>Includes any change disrupting access to vCenter or vSphere hosts, and management-network-impacting changes.</p>

<table>
  <tr><th>Category</th><th>Setting</th><th>Baseline</th><th>Measured</th><th>Reason</th><th>Mgmt Network?</th></tr>
  {% for f in findings %}
  <tr>
    <td>{{ f.category.value }}</td>
    <td>{{ f.setting_key }}</td>
    <td>{{ f.baseline_value }}</td>
    <td>{{ f.measured_value }}</td>
    <td>{{ f.breaking_reason }}</td>
    <td>{% if f.impacts_management_network %}<span class="badge badge-mgmt">Yes</span>{% else %}No{% endif %}</td>
  </tr>
  {% else %}
  <tr><td colspan="6">No breaking changes detected.</td></tr>
  {% endfor %}
</table>
{% endblock %}
FILEEOF

cat <<'FILEEOF' > templates/reports/remediation_history.html
{% extends "base.html" %}
{% block content %}
<h2>Remediation History</h2>

<table>
  <tr>
    <th>Category</th><th>Setting</th><th>Baseline</th><th>Measured (at detection)</th>
    <th>Status</th><th>First Detected</th><th>Resolved At</th>
  </tr>
  {% for f in findings %}
  <tr>
    <td>{{ f.category.value }}</td>
    <td>{{ f.setting_key }}</td>
    <td>{{ f.baseline_value }}</td>
    <td>{{ f.measured_value }}</td>
    <td><span class="badge badge-{{ 'open' if f.status.value == 'open' else 'resolved' }}">{{ f.status.value }}</span></td>
    <td>{{ f.first_detected_at }}</td>
    <td>{{ f.resolved_at or "-" }}</td>
  </tr>
  {% else %}
  <tr><td colspan="7">No history available yet.</td></tr>
  {% endfor %}
</table>
{% endblock %}
FILEEOF

cat <<'FILEEOF' > templates/backup/backup.html
{% extends "base.html" %}
{% block content %}
<h2>Database Backups</h2>

<form method="POST" action="{{ url_for('backup.run_backup') }}">
  <button type="submit">Run Backup Now</button>
</form>

<table>
  <tr><th>Backup File</th><th></th></tr>
  {% for f in files %}
  <tr>
    <td>{{ f }}</td>
    <td><a href="{{ url_for('backup.download_backup', filename=f) }}">Download</a></td>
  </tr>
  {% else %}
  <tr><td colspan="2">No backups yet.</td></tr>
  {% endfor %}
</table>
{% endblock %}
FILEEOF

# ----------------------------------------------------------------------
# deploy/
# ----------------------------------------------------------------------

cat <<'FILEEOF' > deploy/setup_server.sh
#!/usr/bin/env bash
set -euo pipefail

APP_NAME="vcf-drift-app"
APP_USER="vcfdrift"
APP_DIR="/opt/${APP_NAME}"
VENV_DIR="${APP_DIR}/venv"
DB_NAME="vcf_drift"
DB_USER="vcf_drift_user"
DB_PASSWORD="$(openssl rand -base64 24)"
DOMAIN_OR_IP="${1:-_}"

echo "==> Updating system packages"
apt-get update -y && apt-get upgrade -y

echo "==> Installing dependencies"
apt-get install -y python3 python3-venv python3-pip postgresql postgresql-contrib nginx git curl ufw unzip

echo "==> Creating application user"
id -u "${APP_USER}" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "${APP_USER}"

echo "==> Creating application directory"
mkdir -p "${APP_DIR}"
chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"

echo "==> Configuring PostgreSQL"
sudo -u postgres psql -v ON_ERROR_STOP=1 <<PSQL
DO \$\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}') THEN
      CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASSWORD}';
   END IF;
END
\$\$;

SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}')\gexec
PSQL

echo "${DB_PASSWORD}" > /root/.vcf_drift_db_pass
chmod 600 /root/.vcf_drift_db_pass

echo "==> Deploying application code"
if [ -d "./app_src" ]; then
    cp -r ./app_src/* "${APP_DIR}/"
fi
chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"

echo "==> Creating Python virtual environment"
sudo -u "${APP_USER}" python3 -m venv "${VENV_DIR}"
sudo -u "${APP_USER}" "${VENV_DIR}/bin/pip" install --upgrade pip
[ -f "${APP_DIR}/requirements.txt" ] && sudo -u "${APP_USER}" "${VENV_DIR}/bin/pip" install -r "${APP_DIR}/requirements.txt"

echo "==> Writing .env"
cat > "${APP_DIR}/.env" <<ENV
DATABASE_URL=postgresql://${DB_USER}:${DB_PASSWORD}@localhost:5432/${DB_NAME}
SECRET_KEY=$(openssl rand -hex 32)
FLASK_ENV=production
APP_DIR=${APP_DIR}
BACKUP_DIR=${APP_DIR}/backups
GIT_REPO_DIR=${APP_DIR}/git_repo
BASELINE_ENVIRONMENT_NAME=baseline
MEASURED_ENVIRONMENT_NAME=measured
BASELINE_VCENTER_HOST=changeme
BASELINE_VCENTER_USER=changeme
BASELINE_VCENTER_PASSWORD=changeme
ENV
chown "${APP_USER}:${APP_USER}" "${APP_DIR}/.env"
chmod 600 "${APP_DIR}/.env"

mkdir -p "${APP_DIR}/backups"
chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}/backups"

echo "==> Installing systemd service"
cp ./deploy/vcf-drift-webapp.service /etc/systemd/system/${APP_NAME}.service
systemctl daemon-reload
systemctl enable "${APP_NAME}"
systemctl restart "${APP_NAME}"

echo "==> Configuring Nginx"
sed "s/SERVER_NAME_PLACEHOLDER/${DOMAIN_OR_IP}/g" ./deploy/nginx_vcf_drift.conf > /etc/nginx/sites-available/${APP_NAME}
ln -sf /etc/nginx/sites-available/${APP_NAME} /etc/nginx/sites-enabled/${APP_NAME}
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx

echo "==> Configuring firewall"
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable

echo "==> Setting up nightly backup cron"
cp ./deploy/backup_db.sh "${APP_DIR}/backup_db.sh"
chmod +x "${APP_DIR}/backup_db.sh"
chown "${APP_USER}:${APP_USER}" "${APP_DIR}/backup_db.sh"
( crontab -u "${APP_USER}" -l 2>/dev/null; echo "0 2 * * * ${APP_DIR}/backup_db.sh >> ${APP_DIR}/backups/backup.log 2>&1" ) | crontab -u "${APP_USER}" -

echo "==> Setup complete. Edit ${APP_DIR}/.env with real vCenter/Git credentials, then: systemctl restart ${APP_NAME}"
FILEEOF

cat <<'FILEEOF' > deploy/vcf-drift-webapp.service
[Unit]
Description=VCF Config Drift Comparison Web App
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=vcfdrift
Group=vcfdrift
WorkingDirectory=/opt/vcf-drift-app
EnvironmentFile=/opt/vcf-drift-app/.env
ExecStart=/opt/vcf-drift-app/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:8000 --timeout 120 app:app
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
FILEEOF

cat <<'FILEEOF' > deploy/nginx_vcf_drift.conf
server {
    listen 80;
    server_name SERVER_NAME_PLACEHOLDER;
    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
FILEEOF

cat <<'FILEEOF' > deploy/backup_db.sh
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/vcf-drift-app"
ENV_FILE="${APP_DIR}/.env"
BACKUP_DIR="${APP_DIR}/backups"
RETENTION_DAYS=30

[ -f "${ENV_FILE}" ] && export $(grep -v '^#' "${ENV_FILE}" | xargs)
[ -z "${DATABASE_URL:-}" ] && { echo "ERROR: DATABASE_URL not set."; exit 1; }

mkdir -p "${BACKUP_DIR}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/vcf_drift_backup_${TIMESTAMP}.sql.gz"

echo "==> Backing up to ${BACKUP_FILE}"
pg_dump "${DATABASE_URL}" | gzip > "${BACKUP_FILE}"

echo "==> Pruning backups older than ${RETENTION_DAYS} days"
find "${BACKUP_DIR}" -name "vcf_drift_backup_*.sql.gz" -mtime +"${RETENTION_DAYS}" -delete

ls -lh "${BACKUP_DIR}"
FILEEOF

cat <<'FILEEOF' > deploy/restore_db.sh
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/vcf-drift-app"
ENV_FILE="${APP_DIR}/.env"
SERVICE_NAME="vcf-drift-app"

[ "$#" -ne 1 ] && { echo "Usage: $0 <backup_file.sql.gz>"; exit 1; }
BACKUP_FILE="$1"
[ ! -f "${BACKUP_FILE}" ] && { echo "ERROR: File not found: ${BACKUP_FILE}"; exit 1; }

[ -f "${ENV_FILE}" ] && export $(grep -v '^#' "${ENV_FILE}" | xargs)
[ -z "${DATABASE_URL:-}" ] && { echo "ERROR: DATABASE_URL not set."; exit 1; }

echo "==> Stopping application service"
systemctl stop "${SERVICE_NAME}"

echo "==> Restoring from ${BACKUP_FILE}"
gunzip -c "${BACKUP_FILE}" | psql "${DATABASE_URL}"

echo "==> Restarting application service"
systemctl start "${SERVICE_NAME}"

echo "==> Restore complete."
FILEEOF

chmod +x deploy/setup_server.sh deploy/backup_db.sh deploy/restore_db.sh

cd ..

echo ""
echo "==> Repository files created under: ${TARGET_DIR}/"
echo "==> Next steps:"
echo "    cd ${TARGET_DIR}"
echo "    git init"
echo "    git add ."
echo "    git commit -m 'Initial commit: VCF config drift comparison app'"
echo ""
echo "For local dev testing:"
echo "    python3 -m venv venv && source venv/bin/activate"
echo "    pip install -r requirements.txt"
echo "    cp .env.example .env"
echo "    python app.py"