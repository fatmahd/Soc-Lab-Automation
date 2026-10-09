#!/usr/bin/env bash
set -euo pipefail

# Apply Phase 4 custom rules + TheHive integration to Wazuh manager container.
# Usage:
#   sudo PROJECT_DIR=/opt/soc-lab MANAGER_CONTAINER=single-node-wazuh.manager-1 bash scripts/apply_phase4_wazuh_docker.sh
# Optional:
#   ENABLE_THEHIVE_INTEGRATION=true to deploy TheHive integration.

PROJECT_DIR="${PROJECT_DIR:-/opt/soc-lab}"
MANAGER_CONTAINER="${MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
ENABLE_THEHIVE_INTEGRATION="${ENABLE_THEHIVE_INTEGRATION:-true}"
ANALYSISD_DECODER_ORDER_SIZE="${ANALYSISD_DECODER_ORDER_SIZE:-1024}"
RULES_DIR="$PROJECT_DIR/config/wazuh/rules"
LEGACY_RULES_FILE="$PROJECT_DIR/config/wazuh/local_rules_phase4.xml"

source_rule_files=()

if [[ ! -d "$PROJECT_DIR" ]]; then
  echo "[ERROR] PROJECT_DIR not found: $PROJECT_DIR"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[ERROR] docker command not found"
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -qx "$MANAGER_CONTAINER"; then
  echo "[ERROR] Wazuh manager container not running: $MANAGER_CONTAINER"
  echo "Use: docker ps --format '{{.Names}}'"
  exit 1
fi

if ! [[ "$ANALYSISD_DECODER_ORDER_SIZE" =~ ^[0-9]+$ ]]; then
  echo "[WARN] ANALYSISD_DECODER_ORDER_SIZE is not numeric: $ANALYSISD_DECODER_ORDER_SIZE"
  echo "[WARN] Falling back to 1024"
  ANALYSISD_DECODER_ORDER_SIZE=1024
fi

if (( ANALYSISD_DECODER_ORDER_SIZE > 1024 )); then
  echo "[WARN] ANALYSISD_DECODER_ORDER_SIZE too high for this Wazuh build: $ANALYSISD_DECODER_ORDER_SIZE"
  echo "[WARN] Capping to 1024"
  ANALYSISD_DECODER_ORDER_SIZE=1024
fi

if (( ANALYSISD_DECODER_ORDER_SIZE < 64 )); then
  echo "[WARN] ANALYSISD_DECODER_ORDER_SIZE too low: $ANALYSISD_DECODER_ORDER_SIZE"
  echo "[WARN] Raising to 64"
  ANALYSISD_DECODER_ORDER_SIZE=64
fi

echo "[INFO] Copying local rules"
if [[ -d "$RULES_DIR" ]]; then
  mapfile -t source_rule_files < <(
    find "$RULES_DIR" -type f -name '*.xml' \
      | awk -F'/' '{print $NF "\t" $0}' \
      | sort -V \
      | cut -f2-
  )
  if [[ ${#source_rule_files[@]} -eq 0 ]]; then
    echo "[ERROR] No XML rule files found in $RULES_DIR"
    exit 1
  fi

  declare -A seen_rule_names=()

  for rule_file in "${source_rule_files[@]}"; do
    rule_name="$(basename "$rule_file")"

    if [[ -n "${seen_rule_names[$rule_name]:-}" ]]; then
      echo "[ERROR] Duplicate rule filename detected: $rule_name"
      echo "[ERROR] Conflicting files: ${seen_rule_names[$rule_name]} and $rule_file"
      echo "[ERROR] Use unique basenames for all XML files under $RULES_DIR"
      exit 1
    fi
    seen_rule_names["$rule_name"]="$rule_file"

    echo "[INFO] Copying rule file: $rule_name"
    docker cp "$rule_file" "$MANAGER_CONTAINER:/var/ossec/etc/rules/$rule_name"
  done
else
  if [[ ! -f "$LEGACY_RULES_FILE" ]]; then
    echo "[ERROR] Missing both modular rules directory ($RULES_DIR) and legacy rules file ($LEGACY_RULES_FILE)"
    exit 1
  fi

  source_rule_files=("$LEGACY_RULES_FILE")
  docker cp "$LEGACY_RULES_FILE" "$MANAGER_CONTAINER:/var/ossec/etc/rules/local_rules.xml"
fi

if [[ "$ENABLE_THEHIVE_INTEGRATION" == "true" ]]; then
  if [[ ! -f "$PROJECT_DIR/config/.env" ]]; then
    echo "[ERROR] Missing $PROJECT_DIR/config/.env"
    exit 1
  fi

  echo "[INFO] Copying integration script"
  docker cp "$PROJECT_DIR/automation/wazuh_to_thehive.py" "$MANAGER_CONTAINER:/var/ossec/integrations/custom-wazuh-thehive"

  echo "[INFO] Copying integration environment"
  docker cp "$PROJECT_DIR/config/.env" "$MANAGER_CONTAINER:/var/ossec/integrations/.env"

  echo "[INFO] Setting permissions inside container"
  docker exec "$MANAGER_CONTAINER" chown root:wazuh /var/ossec/integrations/custom-wazuh-thehive /var/ossec/integrations/.env
  docker exec "$MANAGER_CONTAINER" chmod 750 /var/ossec/integrations/custom-wazuh-thehive
  docker exec "$MANAGER_CONTAINER" chmod 640 /var/ossec/integrations/.env

  echo "[INFO] Ensuring Python requests dependency is available in manager container"
  docker exec "$MANAGER_CONTAINER" sh -lc 'set -e; if ! python3 -m pip --version >/dev/null 2>&1; then if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip; elif command -v dnf >/dev/null 2>&1; then dnf install -y python3-pip; elif command -v yum >/dev/null 2>&1; then yum install -y python3-pip; elif command -v apk >/dev/null 2>&1; then apk add --no-cache py3-pip; else python3 -m ensurepip --upgrade; fi; fi; python3 -m pip install --no-cache-dir requests'

  echo "[INFO] Ensuring custom-wazuh-thehive integration block exists in ossec.conf"
  docker exec "$MANAGER_CONTAINER" sh -lc 'set -e; CONF=/var/ossec/etc/ossec.conf; if ! grep -q "<name>custom-wazuh-thehive</name>" "$CONF"; then sed -i "/<\\/ossec_config>/i\\
  <integration>\\
    <name>custom-wazuh-thehive<\\/name>\\
     <hook_url>http://192.168.99.15:9000</hook_url>\\
    <level>10<\\/level>\\
    <alert_format>json<\\/alert_format>\\
  <\\/integration>" "$CONF"; fi'

  echo "[INFO] Deduplicating custom-wazuh-thehive integration blocks (keep only one)"
  docker exec -i "$MANAGER_CONTAINER" python3 - <<'PY'
from pathlib import Path
import re

conf_path = Path("/var/ossec/etc/ossec.conf")
text = conf_path.read_text(encoding="utf-8")

pattern = re.compile(r"\n\s*<integration>\s*\n\s*<name>custom-wazuh-thehive</name>\s*\n\s*<level>10</level>\s*\n\s*<alert_format>json</alert_format>\s*\n\s*</integration>\s*\n", re.MULTILINE)
matches = list(pattern.finditer(text))

if len(matches) <= 1:
    print(f"[INFO] custom-wazuh-thehive integration blocks found: {len(matches)}")
    raise SystemExit(0)

first_start, first_end = matches[0].span()
first_block = text[first_start:first_end]

text_without_all = pattern.sub("\n", text)
insert_anchor = "</ossec_config>"
anchor_pos = text_without_all.rfind(insert_anchor)

if anchor_pos == -1:
    print("[WARN] Could not find </ossec_config>; skipping dedup write")
    raise SystemExit(0)

rebuilt = text_without_all[:anchor_pos] + first_block + text_without_all[anchor_pos:]
conf_path.write_text(rebuilt, encoding="utf-8")
print(f"[INFO] Removed {len(matches) - 1} duplicate integration block(s)")
PY
else
  echo "[INFO] ENABLE_THEHIVE_INTEGRATION=false -> Wazuh-only mode"
  echo "[INFO] Removing custom-wazuh-thehive integration blocks from ossec.conf (if present)"
  docker exec -i "$MANAGER_CONTAINER" python3 - <<'PY'
from pathlib import Path
import re

conf_path = Path("/var/ossec/etc/ossec.conf")
text = conf_path.read_text(encoding="utf-8")
pattern = re.compile(r"\n\s*<integration>\s*\n\s*<name>custom-wazuh-thehive</name>\s*\n\s*<level>10</level>\s*\n\s*<alert_format>json</alert_format>\s*\n\s*</integration>\s*\n", re.MULTILINE)
new_text, count = pattern.subn("\n", text)
if count > 0:
    conf_path.write_text(new_text, encoding="utf-8")
print(f"[INFO] Removed {count} custom integration block(s)")
PY
fi

echo "[INFO] Restarting manager service inside container"
echo "[INFO] Tuning analysisd JSON decoder field limit"
docker exec "$MANAGER_CONTAINER" sh -lc "set -e; F=/var/ossec/etc/local_internal_options.conf; touch \"\$F\"; if grep -q '^analysisd.decoder_order_size=' \"\$F\"; then sed -i 's/^analysisd\\.decoder_order_size=.*/analysisd.decoder_order_size=${ANALYSISD_DECODER_ORDER_SIZE}/' \"\$F\"; else echo \"analysisd.decoder_order_size=${ANALYSISD_DECODER_ORDER_SIZE}\" >> \"\$F\"; fi; grep -n '^analysisd.decoder_order_size=' \"\$F\""
docker exec "$MANAGER_CONTAINER" /var/ossec/bin/wazuh-control restart

echo "[INFO] Verifying Phase 4 rule IDs in /var/ossec/etc/rules"
mapfile -t required_ids < <(
  grep -h -oE '<rule id="[0-9]+"' "${source_rule_files[@]}" \
    | sed -E 's/.*"([0-9]+)"/\1/' \
    | sort -n -u
)

if [[ ${#required_ids[@]} -eq 0 ]]; then
  echo "[ERROR] Could not extract any rule IDs from source rules files"
  exit 1
fi

missing_ids=()

for rid in "${required_ids[@]}"; do
  if ! docker exec "$MANAGER_CONTAINER" sh -lc "grep -Rqs \"<rule id=\\\"${rid}\\\"\" /var/ossec/etc/rules"; then
    missing_ids+=("$rid")
  fi
done

ids_pattern="$(printf '%s\n' "${required_ids[@]}" | paste -sd'|' -)"
docker exec "$MANAGER_CONTAINER" sh -lc "grep -REn \"${ids_pattern}\" /var/ossec/etc/rules/*.xml" || true

if [[ ${#missing_ids[@]} -gt 0 ]]; then
  echo "[ERROR] Missing Phase 4 rule IDs in /var/ossec/etc/rules: ${missing_ids[*]}"
  echo "[ERROR] Ensure source rules under $RULES_DIR are up-to-date and re-run the script"
  exit 1
fi

echo "[OK] Phase 4 configuration applied to container $MANAGER_CONTAINER"
