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
