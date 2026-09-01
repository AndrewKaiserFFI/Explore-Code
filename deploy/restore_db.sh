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
