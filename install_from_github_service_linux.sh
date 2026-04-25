#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:-}"

REPO_URL="${REPO_URL:-https://github.com/MEDALI003/Advanced_collectors.git}"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/advanced_collectors}"

MANAGER_BRANCH="${MANAGER_BRANCH:-manager}"
AGENT_BRANCH="${AGENT_BRANCH:-agent}"
MANAGER_PORT="${MANAGER_PORT:-8000}"

MANAGER_HOST="${MANAGER_HOST:-127.0.0.1}"
MANAGER_URL="${MANAGER_URL:-http://${MANAGER_HOST}:${MANAGER_PORT}/ingest}"

SIEM_API_KEY="${SIEM_API_KEY:-strong-api-key}"
SIEM_HMAC_SECRET="${SIEM_HMAC_SECRET:-strong-hmac-secret}"
RUN_USER="${RUN_USER:-root}"

MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_DATABASE="${MYSQL_DATABASE:-siem}"
MYSQL_USER="${MYSQL_USER:-siem_user}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-strong_password}"

OLLAMA_HOST="${OLLAMA_HOST:-192.168.153.1}"
OLLAMA_PORT="${OLLAMA_PORT:-11434}"
OLLAMA_URL="${OLLAMA_URL:-http://${OLLAMA_HOST}:${OLLAMA_PORT}/api/generate}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama1:8b}"

SIEM_MAX_LOGS="${SIEM_MAX_LOGS:-500}"
SIEM_MAX_ITEMS="${SIEM_MAX_ITEMS:-250}"

usage() {
  cat <<EOF
Usage:
  sudo bash install_from_github_service_linux.sh manager
  sudo MANAGER_HOST=10.0.0.15 bash install_from_github_service_linux.sh agent

Optional variables:
  REPO_URL, INSTALL_ROOT
  MANAGER_BRANCH, AGENT_BRANCH
  MANAGER_HOST, MANAGER_PORT, MANAGER_URL
  SIEM_API_KEY, SIEM_HMAC_SECRET
  MYSQL_HOST, MYSQL_PORT, MYSQL_DATABASE, MYSQL_USER, MYSQL_PASSWORD
  OLLAMA_HOST, OLLAMA_PORT, OLLAMA_URL, OLLAMA_MODEL
  SIEM_MAX_LOGS, SIEM_MAX_ITEMS
  RUN_USER
EOF
}

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Run this script with sudo/root."
    exit 1
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing command: $1"
    exit 1
  }
}

install_pkgs() {
  need_cmd apt-get
  export DEBIAN_FRONTEND=noninteractive

  apt-get update
  apt-get install -y \
    git \
    curl \
    python3 \
    python3-venv \
    python3-pip \
    mariadb-server \
    mariadb-client
}

ensure_mariadb() {
  systemctl enable --now mariadb
  systemctl restart mariadb

  systemctl is-active --quiet mariadb || {
    echo "MariaDB failed to start."
    exit 1
  }
}

setup_mysql_db() {
  mysql <<EOF
CREATE DATABASE IF NOT EXISTS \`${MYSQL_DATABASE}\`;

CREATE USER IF NOT EXISTS '${MYSQL_USER}'@'localhost'
IDENTIFIED BY '${MYSQL_PASSWORD}';

CREATE USER IF NOT EXISTS '${MYSQL_USER}'@'127.0.0.1'
IDENTIFIED BY '${MYSQL_PASSWORD}';

GRANT ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.*
TO '${MYSQL_USER}'@'localhost';

GRANT ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.*
TO '${MYSQL_USER}'@'127.0.0.1';

FLUSH PRIVILEGES;
EOF
}

clone_branch() {
  local branch="$1"
  local dest="$2"

  if [ ! -d "$dest/.git" ]; then
    git clone --branch "$branch" "$REPO_URL" "$dest"
  else
    if [ -f "$dest/.env" ]; then
      cp "$dest/.env" "$dest/.env.backup"
    fi

    git -C "$dest" fetch --all
    git -C "$dest" checkout "$branch"

    if ! git -C "$dest" pull; then
      echo "git pull failed in $dest"
      echo "Local files may be blocking the update."
      exit 1
    fi
  fi
}

write_manager_env() {
  local mgr="$1"

  cat > "$mgr/.env" <<EOF
SIEM_API_KEY=$SIEM_API_KEY
SIEM_HMAC_SECRET=$SIEM_HMAC_SECRET
SIEM_MAX_LOGS=$SIEM_MAX_LOGS
SIEM_MAX_ITEMS=$SIEM_MAX_ITEMS

MYSQL_HOST=$MYSQL_HOST
MYSQL_PORT=$MYSQL_PORT
MYSQL_DATABASE=$MYSQL_DATABASE
MYSQL_USER=$MYSQL_USER
MYSQL_PASSWORD=$MYSQL_PASSWORD

OLLAMA_URL=$OLLAMA_URL
OLLAMA_MODEL=$OLLAMA_MODEL
EOF
}

write_agent_config() {
  local agent="$1"

  cat > "$agent/config.json" <<EOF
{
  "manager_url": "$MANAGER_URL",
  "api_key": "$SIEM_API_KEY",
  "hmac_secret": "$SIEM_HMAC_SECRET",
  "interval_seconds": 2,
  "watch_directory": "/etc",
  "log_targets": {
    "linux": ["ssh", "sshd", "sudo", "cron", "systemd", "kernel", "ufw", "auditd", "apache2", "nginx", "mysql", "docker"],
    "windows": ["Security", "System", "Application"],
    "darwin": ["sshd", "sudo"]
  },
  "watch_services": {
    "linux": ["ssh", "sshd", "cron", "rsyslog", "systemd-journald", "ufw", "auditd", "apache2", "nginx", "mysql", "docker"],
    "windows": ["WinDefend", "EventLog", "Spooler"],
    "darwin": ["com.openssh.sshd"]
  },
  "limits": {
    "max_file_scan": 20000,
    "max_network_connections": 300,
    "top_processes": 25
  },
  "tls_verify": true
}
EOF
}

install_manager_python_deps() {
  local mgr="$1"

  python3 -m venv "$mgr/.venv"
  "$mgr/.venv/bin/python" -m pip install --upgrade pip

  if [ -f "$mgr/requirements.txt" ]; then
    "$mgr/.venv/bin/python" -m pip install -r "$mgr/requirements.txt"
  fi

  "$mgr/.venv/bin/python" -m pip install \
    requests \
    mysql-connector-python
}

test_ollama_connection() {
  echo "[*] Testing Ollama connection: $OLLAMA_URL"

  local base_url
  base_url="${OLLAMA_URL%/api/generate}"

  if curl -s --connect-timeout 3 "$base_url/api/tags" >/dev/null 2>&1; then
    echo "[+] Ollama reachable at $base_url"
  else
    echo "[!] Warning: Ollama is not reachable at $base_url"
    echo "    Manager will install, but AI analysis will fail until Ollama is reachable."
  fi
}

create_manager_service() {
  local mgr="$1"

  cat > /etc/systemd/system/advanced-collectors-manager.service <<EOF
[Unit]
Description=Advanced Collectors Manager
After=network-online.target mariadb.service
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$mgr
EnvironmentFile=$mgr/.env
Environment=PYTHONUNBUFFERED=1
ExecStart=$mgr/.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port $MANAGER_PORT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable advanced-collectors-manager.service
  systemctl restart advanced-collectors-manager.service
  systemctl status advanced-collectors-manager.service --no-pager || true
}

create_agent_service() {
  local agent="$1"

  cat > /etc/systemd/system/advanced-collectors-agent.service <<EOF
[Unit]
Description=Advanced Collectors Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$agent
Environment=PYTHONUNBUFFERED=1
ExecStart=$agent/.venv/bin/python $agent/agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable advanced-collectors-agent.service
  systemctl restart advanced-collectors-agent.service
  systemctl status advanced-collectors-agent.service --no-pager || true
}

install_manager() {
  local dest="$INSTALL_ROOT/manager"
  local host_ip

  mkdir -p "$INSTALL_ROOT"

  install_pkgs
  ensure_mariadb
  setup_mysql_db

  clone_branch "$MANAGER_BRANCH" "$dest"

  install_manager_python_deps "$dest"

  write_manager_env "$dest"
  test_ollama_connection
  create_manager_service "$dest"

  host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  host_ip="${host_ip:-127.0.0.1}"

  echo
  echo "Manager installed as service."
  echo "Docs: http://$host_ip:$MANAGER_PORT/docs"
  echo "MySQL database: $MYSQL_DATABASE"
  echo "MySQL user: $MYSQL_USER"
  echo "Ollama URL: $OLLAMA_URL"
  echo "Ollama model: $OLLAMA_MODEL"
}

install_agent() {
  local dest="$INSTALL_ROOT/agent"

  mkdir -p "$INSTALL_ROOT"

  install_pkgs
  clone_branch "$AGENT_BRANCH" "$dest"

  python3 -m venv "$dest/.venv"
  "$dest/.venv/bin/python" -m pip install --upgrade pip

  if [ -f "$dest/requirements.txt" ]; then
    "$dest/.venv/bin/python" -m pip install -r "$dest/requirements.txt"
  fi

  write_agent_config "$dest"
  create_agent_service "$dest"

  echo
  echo "Agent installed as service."
  echo "Current manager URL: $MANAGER_URL"
}

main() {
  [ -n "$ROLE" ] || {
    usage
    exit 1
  }

  require_root

  case "$ROLE" in
    manager)
      install_manager
      ;;
    agent)
      install_agent
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"