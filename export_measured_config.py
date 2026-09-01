# collector/export_measured_config.py
"""
Standalone export utility.

Run this directly inside/against the MEASURED environment (which has no
connectivity to the web app or baseline environment). It:
  1. Authenticates to vCenter via the VMwareConfigCollector.
  2. Pulls the full configuration state.
  3. Packages the result (JSON + metadata) into a timestamped folder/zip.
  4. Optionally stages/commits/pushes the package to a Git repository,
     so the web app can later ingest it from Git.

Usage:
    export VCENTER_HOST=vcenter.measured.local
    export VCENTER_USER=administrator@vsphere.local
    export VCENTER_PASSWORD=********
    export GIT_REPO_DIR=/path/to/local/git/repo
    export ENVIRONMENT_NAME=measured-site-b

    python3 export_measured_config.py --push-to-git
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
    """
    Writes the collected config plus metadata into a timestamped folder,
    then zips it. Returns the path to the zip file.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    package_name = f"{environment_name}_{timestamp}"
    package_dir = os.path.join(output_root, package_name)
    os.makedirs(package_dir, exist_ok=True)

    config_path = os.path.join(package_dir, "config.json")
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2, default=str)

    metadata = {
        "environment_name": environment_name,
        "captured_at_utc": timestamp,
        "role": "measured",
        "collector_version": "1.0",
    }
    metadata_path = os.path.join(package_dir, "metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    zip_path = os.path.join(output_root, f"{package_name}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(package_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, package_dir)
                zipf.write(file_path, arcname)

    logger.info(f"Packaged export at: {zip_path}")
    return zip_path


def push_to_git(git_repo_dir: str, package_path: str, environment_name: str):
    """
    Copies the package into the local Git repo working directory, then
    stages, commits, and pushes it. Assumes the repo is already cloned
    and configured with valid remote credentials on this host.
    """
    if not os.path.isdir(os.path.join(git_repo_dir, ".git")):
        raise RuntimeError(f"{git_repo_dir} is not a valid git repository.")

    dest_dir = os.path.join(git_repo_dir, "exports", environment_name)
    os.makedirs(dest_dir, exist_ok=True)

    dest_path = os.path.join(dest_dir, os.path.basename(package_path))
    shutil.copy2(package_path, dest_path)

    commit_message = f"Add measured config export: {os.path.basename(package_path)}"

    subprocess.run(["git", "-C", git_repo_dir, "add", dest_path], check=True)
    subprocess.run(
        ["git", "-C", git_repo_dir, "commit", "-m", commit_message], check=True
    )
    subprocess.run(["git", "-C", git_repo_dir, "push"], check=True)

    logger.info(f"Pushed export to Git repo at {git_repo_dir}: {dest_path}")


def main():
    parser = argparse.ArgumentParser(description="Export measured VCF environment config.")
    parser.add_argument(
        "--output-dir",
        default="./exports",
        help="Local directory to write the packaged export (default: ./exports)",
    )
    parser.add_argument(
        "--push-to-git",
        action="store_true",
        help="Copy, commit, and push the package to the configured Git repo.",
    )
    args = parser.parse_args()

    vcenter_host = get_required_env("VCENTER_HOST")
    vcenter_user = get_required_env("VCENTER_USER")
    vcenter_password = get_required_env("VCENTER_PASSWORD")
    environment_name = os.environ.get("ENVIRONMENT_NAME", "measured")

    os.makedirs(args.output_dir, exist_ok=True)

    collector = VMwareConfigCollector(
        vcenter_host=vcenter_host,
        username=vcenter_user,
        password=vcenter_password,
    )

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