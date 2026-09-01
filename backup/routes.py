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
