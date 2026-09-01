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
