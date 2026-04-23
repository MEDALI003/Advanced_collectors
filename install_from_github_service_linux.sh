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

usage() {
  cat <<EOF
Usage:
  sudo bash install_from_github_service_linux.sh manager
  sudo MANAGER_HOST=10.0.0.15 bash install_from_github_service_linux.sh agent

Environment variables:
  REPO_URL, INSTALL_ROOT
  MANAGER_BRANCH, AGENT_BRANCH
  MANAGER_HOST, MANAGER_PORT, MANAGER_URL
  SIEM_API_KEY, SIEM_HMAC_SECRET
  RUN_USER

Examples:
  sudo SIEM_API_KEY=mykey SIEM_HMAC_SECRET=mysecret bash install_from_github_service_linux.sh manager
  sudo MANAGER_URL=http://siem-manager.local:8000/ingest bash install_from_github_service_linux.sh agent
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

install_deps() {
  need_cmd git
  need_cmd python3
  need_cmd systemctl
  python3 -m pip --version >/dev/null 2>&1 || {
    echo "python3-pip is missing. Install pip for Python 3 first."
    exit 1
  }
}

clone_branch() {
  local branch="$1"
  local dest="$2"

  if [ ! -d "$dest/.git" ]; then
    git clone --branch "$branch" "$REPO_URL" "$dest"
  else
    git -C "$dest" fetch --all
    git -C "$dest" checkout "$branch"
    git -C "$dest" pull
  fi
}

write_manager_env() {
  local mgr="$1"

  cat > "$mgr/.env" <<EOF
SIEM_API_KEY=$SIEM_API_KEY
SIEM_HMAC_SECRET=$SIEM_HMAC_SECRET
EOF
}

write_agent_config() {
  local agent="$1"

  mkdir -p "$agent/watchdir"

  cat > "$agent/config.json" <<EOF
{
  "manager_url": "$MANAGER_URL",
  "api_key": "$SIEM_API_KEY",
  "hmac_secret": "$SIEM_HMAC_SECRET",
  "interval_seconds": 30,
  "watch_directory": "./watchdir",
  "log_targets": {
    "linux": ["ssh", "cron"],
    "windows": ["Security", "System"],
    "darwin": ["sshd", "sudo"]
  },
  "watch_services": {
    "linux": ["ssh", "cron"],
    "windows": ["WinDefend", "EventLog", "Spooler"],
    "darwin": ["com.openssh.sshd"]
  },
  "limits": {
    "max_file_scan": 5000,
    "max_network_connections": 100,
    "top_processes": 10
  },
  "tls_verify": true
}
EOF
}

create_manager_service() {
  local mgr="$1"

  cat > /etc/systemd/system/advanced-collectors-manager.service <<EOF
[Unit]
Description=Advanced Collectors Manager
After=network-online.target
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
  clone_branch "$MANAGER_BRANCH" "$dest"

  python3 -m venv "$dest/.venv"
  "$dest/.venv/bin/python" -m pip install --upgrade pip
  "$dest/.venv/bin/python" -m pip install -r "$dest/requirements.txt"

  write_manager_env "$dest"
  create_manager_service "$dest"

  host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  host_ip="${host_ip:-127.0.0.1}"

  echo
  echo "Manager installed as service."
  echo "Docs: http://$host_ip:$MANAGER_PORT/docs"
}

install_agent() {
  local dest="$INSTALL_ROOT/agent"

  mkdir -p "$INSTALL_ROOT"
  clone_branch "$AGENT_BRANCH" "$dest"

  python3 -m venv "$dest/.venv"
  "$dest/.venv/bin/python" -m pip install --upgrade pip
  "$dest/.venv/bin/python" -m pip install -r "$dest/requirements.txt"

  write_agent_config "$dest"
  create_agent_service "$dest"

  echo
  echo "Agent installed as service."
  echo "Current manager URL: $MANAGER_URL"
  echo "If manager IP changes, rerun:"
  echo "  sudo MANAGER_HOST=<new-ip> bash $0 agent"
  echo "or use DNS:"
  echo "  sudo MANAGER_URL=http://siem-manager.local:$MANAGER_PORT/ingest bash $0 agent"
}

main() {
  [ -n "$ROLE" ] || {
    usage
    exit 1
  }

  require_root
  install_deps

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