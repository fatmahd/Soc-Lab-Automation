#!/usr/bin/env python3

import json
import os
import sys
import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests


ENV_FILE_DEFAULT = "/var/ossec/integrations/.env"


# Wazuh fields to inspect for each observable type.
# Extend these lists to support additional custom fields.
OBSERVABLE_FIELDS: Dict[str, List[str]] = {
    "ip": [
        "data.srcip",
        "data.src_ip",
        "data.dstip",
        "data.dst_ip",
        "data.source_ip",
        "data.destination_ip",
        "win.eventdata.ipAddress",
        "win.eventdata.sourceIp",
        "win.eventdata.destinationIp",
        "win.eventdata.IpAddress",
    ],
    "url": ["data.url", "data.uri", "win.eventdata.url"],
    "domain": [
        "data.domain",
        "data.hostname",
        "data.dns.question.name",
        "win.eventdata.queryName",
        "win.eventdata.destinationHostname",
    ],
    "hash": [
        "syscheck.md5_after",
        "syscheck.sha1_after",
        "syscheck.sha256_after",
        "data.md5",
        "data.sha1",
        "data.sha256",
        "win.eventdata.md5",
        "win.eventdata.sha256",
    ],
    "filename": [
        "syscheck.path",
        "data.file",
        "data.filename",
        "win.eventdata.image",
        "win.eventdata.targetFilename",
        "win.eventdata.originalFileName",
    ],
    "mail": [
        "data.email",
        "data.sender",
        "data.recipient",
        "data.from",
        "data.to",
    ],
    "other": [
        "data.srcuser",
        "data.dstuser",
        "data.user",
        "data.username",
        "win.eventdata.targetUserName",
        "win.eventdata.subjectUserName",
    ],
    "user-agent": ["data.user_agent", "data.http_user_agent"],
}


# Extra patterns to search in full_log.
LOG_PATTERNS: Dict[str, List[str]] = {
    "ip": [
        r"(?:^|\s)SRC=([0-9a-fA-F\.:]+)",
        r"(?:^|\s)DST=([0-9a-fA-F\.:]+)",
        r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b",
    ],
    "url": [r"(https?://[^\s\"'<>]+)"],
    "mail": [r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"],
    "hash": [
        r"\b([a-fA-F0-9]{64})\b",
        r"\b([a-fA-F0-9]{40})\b",
        r"\b([a-fA-F0-9]{32})\b",
    ],
}


IGNORED_VALUES = {
    "",
    "-",
    "n/a",
    "na",
    "none",
    "null",
    "unknown",
    "system",
    "(null)",
}


def load_env_file(path: str) -> None:
    """
    Charge les variables depuis un fichier .env.
    Les variables déjà présentes dans l'environnement sont conservées.
    """
    if not path or not os.path.isfile(path):
        return

    try:
        with open(path, "r", encoding="utf-8") as env_file:
            for raw_line in env_file:
                line = raw_line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                if "=" not in line:
                    continue

                key, value = line.split("=", 1)

                key = key.strip()
                value = value.strip()

                # Supprime les guillemets externes éventuels.
                if len(value) >= 2:
                    if (
                        value.startswith('"')
                        and value.endswith('"')
                    ) or (
                        value.startswith("'")
                        and value.endswith("'")
                    ):
                        value = value[1:-1]

                os.environ.setdefault(key, value)

    except OSError as exc:
        print(f"[ERROR] Impossible de lire le fichier .env: {exc}")


def load_environment() -> None:
    """
    Charge les variables de configuration.
    """
    candidates = [
        os.getenv("SOC_ENV_FILE", ""),
        ENV_FILE_DEFAULT,
        os.path.join(os.getcwd(), ".env"),
    ]

    for candidate in candidates:
        if candidate:
            load_env_file(candidate)


def parse_payload(raw_content: str) -> Dict[str, Any]:
    """
    Analyse un payload JSON classique ou un fichier contenant plusieurs lignes JSON.
    """
    raw_content = raw_content.strip()

    if not raw_content:
        return {}

    # Cas standard : un document JSON complet.
    try:
        data = json.loads(raw_content)

        # Certains formats peuvent contenir une liste d'alertes.
        if isinstance(data, list):
            if not data:
                return {}

            last_item = data[-1]
            return last_item if isinstance(last_item, dict) else {}

        return data if isinstance(data, dict) else {}

    except json.JSONDecodeError:
        pass

    # Cas NDJSON : on cherche la dernière ligne JSON valide.
    for line in reversed(raw_content.splitlines()):
        line = line.strip()

        if not line:
            continue

        try:
            data = json.loads(line)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            continue

    return {}


def load_alert() -> Dict[str, Any]:
    """
    Charge l'alerte depuis un fichier fourni par Wazuh
    ou depuis stdin.
    """
    # Wazuh fournit généralement le chemin du fichier d'alerte
    # parmi les arguments du script.
    for argument in sys.argv[1:]:
        if os.path.isfile(argument):
            try:
                with open(argument, "r", encoding="utf-8") as alert_file:
                    payload = parse_payload(alert_file.read())

                if payload:
                    return payload

            except OSError as exc:
                print(f"[ERROR] Impossible de lire le fichier alerte: {exc}")

    # Fallback : lecture depuis stdin.
    try:
        raw_stdin = sys.stdin.read()
        return parse_payload(raw_stdin)
    except Exception as exc:
        print(f"[ERROR] Impossible de lire stdin: {exc}")
        return {}


def safe_dict(value: Any) -> Dict[str, Any]:
    """
    Retourne un dictionnaire valide.
    """
    return value if isinstance(value, dict) else {}


def safe_string(value: Any, default: str = "unknown") -> str:
    """
    Convertit une valeur en chaîne propre.
    """
    if value is None:
        return default

    value = str(value).strip()

    return value if value else default


def _as_list(value: Any) -> List[str]:
    """
    Normalizes scalar/list values into a list of cleaned strings.
    """
    if value is None:
        return []

    if isinstance(value, list):
        return [safe_string(item, "") for item in value]

    return [safe_string(value, "")]


def _validate(data_type: str, value: str) -> str:
    """
    Returns the cleaned value when valid, otherwise an empty string.
    """
    value = value.strip().strip("\"'")

    if value.lower() in IGNORED_VALUES:
        return ""

    if data_type == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return ""

    if data_type == "hash":
        return (
            value.lower()
            if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value)
            else ""
        )

    if data_type == "url":
        parsed = urlparse(value)
        return value if parsed.scheme in ("http", "https") and parsed.netloc else ""

    if data_type == "domain":
        normalized = value.lower().rstrip(".")

        # Keep IPs in ip type only.
        try:
            ipaddress.ip_address(normalized)
            return ""
        except ValueError:
            pass

        return (
            normalized
            if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", normalized)
            else ""
        )

    if data_type == "mail":
        return (
            value.lower()
            if re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", value)
            else ""
        )

    return value


def get_alert_timestamp(alert: Dict[str, Any]) -> datetime:
    """
    Retourne le timestamp de l'alerte en UTC.
    Fallback: date courante en UTC.
    """
    raw_value = alert.get("timestamp")

    if not raw_value:
        return datetime.now(timezone.utc)

    raw_timestamp = str(raw_value).strip()

    if not raw_timestamp:
        return datetime.now(timezone.utc)

    candidates = [raw_timestamp]

    if raw_timestamp.endswith("Z"):
        candidates.append(raw_timestamp[:-1] + "+00:00")

    # Gère les offsets au format +0000 -> +00:00
    if (
        len(raw_timestamp) >= 5
        and raw_timestamp[-5] in ("+", "-")
        and raw_timestamp[-3] != ":"
    ):
        candidates.append(raw_timestamp[:-2] + ":" + raw_timestamp[-2:])

    for candidate in candidates:
        try:
            dt = datetime.fromisoformat(candidate)

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    return datetime.now(timezone.utc)


def get_dedup_category(rule_info: Dict[str, Any]) -> str:
    """
    Catégorise une alerte pour la déduplication.
    """
    groups = rule_info.get("groups", [])

    if isinstance(groups, str):
        raw_groups = groups.split(",")
    elif isinstance(groups, list):
        raw_groups = groups
    else:
        raw_groups = []

    normalized = {
        safe_string(group, "").lower()
        for group in raw_groups
        if safe_string(group, "")
    }

    if not normalized:
        return "generic"

    if (
        "port_scan" in normalized
        or "portscan_probe" in normalized
        or "portscan_activity" in normalized
    ):
        return "port_scan"

    if "icmp_flood" in normalized:
        return "icmp_flood"

    if "bruteforce" in normalized:
        return "bruteforce"

    # Utilise un groupe fonctionnel pour les autres cas.
    ignored_groups = {
        "attack",
        "network",
        "firewall",
        "windows",
        "linux",
        "sysmon",
        "wazuh",
    }

    functional_groups = sorted(
        group
        for group in normalized
        if group and group not in ignored_groups
    )

    if functional_groups:
        return functional_groups[0]

    return "generic"


def get_nested(alert: Dict[str, Any], path: str) -> Any:
    """
    Récupère une valeur imbriquée depuis un chemin 'a.b.c'.
    """
    current: Any = alert

    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)

    return current


def first_non_empty(alert: Dict[str, Any], paths: List[str]) -> str:
    """
    Retourne la première valeur non vide trouvée dans les chemins fournis.
    """
    for path in paths:
        value = get_nested(alert, path)
        normalized = safe_string(value, "")

        if normalized:
            return normalized

    return ""


def get_dedup_window_seconds() -> int:
    """
    Fenêtre de déduplication en secondes.
    """
    raw_value = os.getenv("WAZUH_DEDUP_WINDOW_SECONDS", "120").strip()

    try:
        parsed = int(raw_value)
        if parsed > 0:
            return parsed
    except ValueError:
        pass

    return 120


def build_source_ref(
    alert: Dict[str, Any],
    rule_info: Dict[str, Any],
    alert_id: str,
    agent_name: str,
) -> str:
    """
    Construit une sourceRef stable pour éviter les doublons.

        Mode par défaut: déduplication par fenêtre de temps et contenu.
    Les modes window et strict incluent une empreinte JSON du payload,
    hors id et timestamp de livraison. Une nouvelle preuve change la reference.
    Si WAZUH_DEDUP_MODE=alert_id, on garde le comportement historique.

        Modes:
            - window: dedup par fenêtre de temps
            - strict: dedup sans fenêtre
            - alert_id/off/disabled: comportement historique

        Scope (WAZUH_DEDUP_SCOPE):
            - category (défaut): regroupe au niveau catégorie
            - rule: inclut le rule_id

        Alias:
            - window_with_rule => mode window + scope rule
    """
    mode = safe_string(
        os.getenv("WAZUH_DEDUP_MODE", "window"),
        "window",
    ).lower()

    if mode in {"alert_id", "off", "disabled"}:
        return f"wazuh-{rule_info.get('id', 'unknown')}-{alert_id}"

    scope = safe_string(
        os.getenv("WAZUH_DEDUP_SCOPE", "category"),
        "category",
    ).lower()

    if mode == "window_with_rule":
        mode = "window"
        scope = "rule"

    category = get_dedup_category(rule_info)
    source_ip = get_source_ip(alert) or "na"
    destination_ip = get_destination_ip(alert) or "na"
    event_timestamp = get_alert_timestamp(alert)
    bucket = int(event_timestamp.timestamp()) // get_dedup_window_seconds()

    # Contexte transversal Linux/Windows pour éviter les doublons logiques.
    protocol = first_non_empty(
        alert,
        [
            "data.protocol",
            "data.proto",
            "win.eventdata.Protocol",
        ],
    ).lower() or "na"

    if protocol == "na":
        full_log = safe_string(alert.get("full_log"), "")
        proto_match = re.search(r"(?:^|\s)PROTO=([^\s]+)", full_log)
        if proto_match:
            protocol = safe_string(proto_match.group(1), "na").lower()

    destination_port = first_non_empty(
        alert,
        [
            "data.dstport",
            "data.dst_port",
            "win.eventdata.destPort",
            "win.eventdata.destinationPort",
            "win.eventdata.DestPort",
        ],
    ) or "na"

    if destination_port == "na":
        full_log = safe_string(alert.get("full_log"), "")
        dpt_match = re.search(r"(?:^|\s)DPT=([0-9]+)", full_log)
        if dpt_match:
            destination_port = safe_string(dpt_match.group(1), "na")

    username = first_non_empty(
        alert,
        [
            "data.user",
            "data.username",
            "data.dstuser",
            "win.eventdata.targetUserName",
            "win.eventdata.TargetUserName",
            "win.eventdata.subjectUserName",
            "win.eventdata.SubjectUserName",
        ],
    ).lower() or "na"

    signature_parts = [
        safe_string(agent_name, "unknown-agent").lower(),
        category,
        source_ip,
        destination_ip,
        protocol,
        destination_port,
        username,
    ]

    if scope == "rule":
        signature_parts.insert(2, safe_string(rule_info.get("id"), "unknown"))

    if mode == "window":
        signature_parts.append(str(bucket))

    evidence = {
        key: value
        for key, value in alert.items()
        if key not in {"id", "timestamp"}
    }
    evidence_json = json.dumps(
        evidence,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    )
    evidence_digest = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
    signature_parts.append(evidence_digest)

    signature = "|".join(signature_parts)

    digest = hashlib.sha1(signature.encode("utf-8")).hexdigest()[:24]
    source_ref = f"wazuh-{category}-{digest}"

    if safe_string(os.getenv("WAZUH_DEDUP_DEBUG", "false"), "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        print(
            "[DEBUG] dedup mode="
            f"{mode} scope={scope} category={category} "
            f"parts={signature_parts} sourceRef={source_ref}"
        )

    return source_ref


def get_rule_information(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extrait les informations de la règle Wazuh.
    """
    rule = safe_dict(alert.get("rule"))

    raw_level = rule.get("level", 0)

    try:
        level = int(raw_level)
    except (TypeError, ValueError):
        level = 0

    return {
        "id": safe_string(rule.get("id"), "unknown"),
        "level": level,
        "description": safe_string(
            rule.get("description"),
            "Wazuh alert",
        ),
        "groups": rule.get("groups", []),
    }


def map_severity(level: int) -> int:
    """
    Conversion du niveau Wazuh vers la sévérité TheHive.

    TheHive :
      1 = Low
      2 = Medium
      3 = High
      4 = Critical
    """
    if level <= 5:
        return 1

    if level <= 9:
        return 2

    if level <= 12:
        return 3

    return 4


def get_source_ip(alert: Dict[str, Any]) -> str:
    """
    Récupère l'adresse IP source depuis plusieurs emplacements possibles.
    """
    data = safe_dict(alert.get("data"))

    candidates = [
        data.get("srcip"),
        data.get("src_ip"),
        data.get("source_ip"),
        alert.get("srcip"),
        alert.get("src_ip"),
        alert.get("source_ip"),
    ]

    for candidate in candidates:
        if candidate:
            return safe_string(candidate, "")

    # Fallback utile pour les logs UFW/iptables présents dans full_log.
    full_log = safe_string(alert.get("full_log"), "")
    match = re.search(r"(?:^|\s)SRC=([^\s]+)", full_log)

    if match:
        return safe_string(match.group(1), "")

    return ""


def get_destination_ip(alert: Dict[str, Any]) -> str:
    """
    Récupère l'adresse IP destination.
    """
    data = safe_dict(alert.get("data"))

    candidates = [
        data.get("dstip"),
        data.get("dst_ip"),
        data.get("destination_ip"),
        alert.get("dstip"),
        alert.get("dst_ip"),
        alert.get("destination_ip"),
    ]

    for candidate in candidates:
        if candidate:
            return safe_string(candidate, "")

    # Fallback utile pour les logs UFW/iptables présents dans full_log.
    full_log = safe_string(alert.get("full_log"), "")
    match = re.search(r"(?:^|\s)DST=([^\s]+)", full_log)

    if match:
        return safe_string(match.group(1), "")

    return ""


def collect_artifacts(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Dynamically extracts real observables from a Wazuh alert.
    """
    found: Dict[tuple, Dict[str, Any]] = {}

    def add(data_type: str, raw_value: str, origin: str) -> None:
        value = _validate(data_type, raw_value)

        if not value:
            return

        key = (data_type, value)

        if key in found:
            return

        tags = [f"wazuh-field:{origin}"]

        if data_type == "ip" and ipaddress.ip_address(value).is_private:
            tags.append("internal")

        found[key] = {
            "dataType": data_type,
            "data": value,
            "message": f"Extrait automatiquement depuis {origin}",
            "tags": tags,
            "ioc": False,
            "sighted": False,
        }

        # A URL also provides a host domain.
        if data_type == "url":
            add("domain", urlparse(value).hostname or "", f"{origin}(host)")

    # 1) Structured fields
    for data_type, paths in OBSERVABLE_FIELDS.items():
        for path in paths:
            for raw in _as_list(get_nested(alert, path)):
                # Sysmon hash format: "SHA256=abc...,MD5=def..."
                if data_type == "hash" and "=" in raw:
                    for part in raw.split(","):
                        add("hash", part.split("=", 1)[-1], path)
                # User accounts can sometimes be emails.
                elif data_type == "other" and "@" in raw:
                    add("mail", raw, path)
                else:
                    add(data_type, raw, path)

    # 2) Raw log search
    full_log = safe_string(alert.get("full_log"), "")

    for data_type, patterns in LOG_PATTERNS.items():
        for pattern in patterns:
            for match in re.findall(pattern, full_log):
                add(data_type, match, "full_log")

    # 3) Involved machine name.
    agent_name = safe_string(safe_dict(alert.get("agent")).get("name"), "")

    if agent_name:
        add("other", agent_name, "agent.name")

    return list(found.values())


def build_description(
    alert: Dict[str, Any],
    rule_info: Dict[str, Any],
    alert_id: str,
    agent_name: str,
) -> str:
    """
    Construit une description lisible dans TheHive.
    """
    source_ip = get_source_ip(alert) or "N/A"
    destination_ip = get_destination_ip(alert) or "N/A"

    full_log = safe_string(
        alert.get("full_log"),
        "N/A",
    )

    original_json = json.dumps(
        alert,
        ensure_ascii=False,
        indent=2,
    )

    return (
        "## Informations Wazuh\n\n"
        f"- **Rule ID :** `{rule_info['id']}`\n"
        f"- **Rule level :** `{rule_info['level']}`\n"
        f"- **Rule description :** {rule_info['description']}\n"
        f"- **Agent :** `{agent_name}`\n"
        f"- **Alert ID :** `{alert_id}`\n"
        f"- **Source IP :** `{source_ip}`\n"
        f"- **Destination IP :** `{destination_ip}`\n\n"
        "## Log original\n\n"
        "```text\n"
        f"{full_log}\n"
        "```\n\n"
        "## Alerte JSON complète\n\n"
        "```json\n"
        f"{original_json}\n"
        "```"
    )


def main() -> int:
    load_environment()

    thehive_url = os.getenv(
        "THEHIVE_URL",
        "http://192.168.99.15:9000",
    ).rstrip("/")

    thehive_api_key = os.getenv(
        "THEHIVE_API_KEY",
        "qn/b2/SBuiKvA9kn9Syo4An4qX+Qicv1",
    ).strip()

    if not thehive_api_key:
        print(
            "[ERROR] THEHIVE_API_KEY est absent. "
            "Configure-le dans /var/ossec/integrations/.env"
        )
        return 1

    alert = load_alert()

    if not alert:
        print(
            "[INFO] Aucun payload Wazuh reçu. "
            "Aucune alerte TheHive ne sera créée."
        )
        return 0

    rule_info = get_rule_information(alert)

    alert_id = safe_string(
        alert.get("id"),
        "unknown",
    )

    agent = safe_dict(alert.get("agent"))

    agent_name = safe_string(
        agent.get("name"),
        "unknown-agent",
    )

    rule_id = rule_info["id"]
    rule_level = rule_info["level"]
    rule_description = rule_info["description"]

    # Titre visible directement dans la liste des alertes TheHive.
    title = (
        f"[WAZUH][RULE-{rule_id}]"
        f"[LEVEL-{rule_level}] "
        f"{rule_description}"
    )

    # Référence stable: même attaque logique => même sourceRef.
    source_ref = build_source_ref(
        alert=alert,
        rule_info=rule_info,
        alert_id=alert_id,
        agent_name=agent_name,
    )

    # Description complète de l'alerte.
    description = build_description(
        alert=alert,
        rule_info=rule_info,
        alert_id=alert_id,
        agent_name=agent_name,
    )

    # Tags visibles dans TheHive.
    tags = [
        "wazuh",
        f"rule:{rule_id}",
        f"level:{rule_level}",
        f"agent:{agent_name}",
    ]

    # Ajoute les groupes Wazuh comme tags.
    rule_groups = rule_info.get("groups", [])

    if isinstance(rule_groups, list):
        for group in rule_groups:
            group_name = safe_string(group, "")

            if group_name:
                tags.append(f"wazuh-group:{group_name}")

    payload = {
        "type": "external",
        "source": "wazuh",
        "sourceRef": source_ref,
        "title": title,
        "description": description,
        "severity": map_severity(rule_level),
        "date": int(
            datetime.now(timezone.utc).timestamp() * 1000
        ),
        "tags": tags,
        "tlp": 2,
        "pap": 2,
        "observables": collect_artifacts(alert),
    }

    headers = {
        "Authorization": f"Bearer {thehive_api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    endpoint = f"{thehive_url}/api/v1/alert"

    try:
        response = requests.post(
            endpoint,
            headers=headers,
            json=payload,
            timeout=20,
        )

    except requests.RequestException as exc:
        print(
            f"[ERROR] Impossible de contacter TheHive: {exc}"
        )
        return 1

    if response.status_code in (200, 201):
        print(
            "[OK] Alerte créée dans TheHive : "
            f"{title}"
        )
        return 0

    duplicate_response = response.status_code == 409

    if response.status_code == 400:
        try:
            error_payload = response.json()
        except ValueError:
            error_payload = {}

        if isinstance(error_payload, dict):
            duplicate_response = (
                error_payload.get("type") == "CreateError"
                and safe_string(error_payload.get("message"), "").startswith(
                    f"Alert external:wazuh:{source_ref} already exists in organisation "
                )
            )

    if duplicate_response:
        print(
            "[INFO] Cette alerte existe déjà dans TheHive : "
            f"{source_ref}"
        )
        return 0

    print(
        "[ERROR] Échec de la requête TheHive : "
        f"{response.status_code} {response.text}"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())