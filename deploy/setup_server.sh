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
