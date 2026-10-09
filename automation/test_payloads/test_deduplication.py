import copy
import io
import json
import os
import sys
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import requests
except ModuleNotFoundError:
    sys.modules["requests"] = types.SimpleNamespace(
        RequestException=Exception,
        post=None,
    )

import wazuh_to_thehive as integration


class DeduplicationTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {
            "WAZUH_DEDUP_MODE": "window",
            "WAZUH_DEDUP_SCOPE": "category",
            "WAZUH_DEDUP_WINDOW_SECONDS": "120",
            "WAZUH_DEDUP_DEBUG": "false",
            "THEHIVE_URL": "http://thehive.invalid",
            "THEHIVE_API_KEY": "test-only",
        })
        environment.start()
        self.addCleanup(environment.stop)
        self.alert = json.loads(
            Path(__file__).with_name("sysmon_network_alert.json").read_text(
                encoding="utf-8"
            )
        )

    def reference(self, alert):
        return integration.build_source_ref(
            alert,
            integration.get_rule_information(alert),
            alert["id"],
            alert["agent"]["name"],
        )

    def test_exact_replay_has_same_reference(self):
        self.assertEqual(self.reference(self.alert), self.reference(copy.deepcopy(self.alert)))

    def test_json_key_order_does_not_change_reference(self):
        reordered = json.loads(json.dumps(self.alert, sort_keys=True))
        self.assertEqual(self.reference(self.alert), self.reference(reordered))

    def test_new_alert_id_alone_does_not_change_evidence(self):
        changed = copy.deepcopy(self.alert)
        changed["id"] = "another-delivery"
        self.assertEqual(self.reference(self.alert), self.reference(changed))

    def test_changed_evidence_has_new_reference(self):
        changes = [
            ("image", r"C:\Windows\Temp\preuve-nouvelle.exe"),
            ("sha256", "d" * 64),
            ("url", "https://example.invalid/new-evidence"),
        ]
        for field, value in changes:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.alert)
                changed["win"]["eventdata"][field] = value
                self.assertNotEqual(self.reference(self.alert), self.reference(changed))
                self.assertEqual(self.reference(changed), self.reference(copy.deepcopy(changed)))

    def test_changed_log_has_new_reference(self):
        changed = copy.deepcopy(self.alert)
        changed["full_log"] = "New evidence in log"
        self.assertNotEqual(self.reference(self.alert), self.reference(changed))

    def test_changed_rule_has_new_reference(self):
        changed = copy.deepcopy(self.alert)
        changed["rule"]["id"] = "120302"
        self.assertNotEqual(self.reference(self.alert), self.reference(changed))

    def test_strict_mode_preserves_new_evidence(self):
        os.environ["WAZUH_DEDUP_MODE"] = "strict"
        changed = copy.deepcopy(self.alert)
        changed["win"]["eventdata"]["image"] = "new-process.exe"
        self.assertNotEqual(self.reference(self.alert), self.reference(changed))
        self.assertEqual(self.reference(self.alert), self.reference(copy.deepcopy(self.alert)))

    def test_alert_id_mode_is_unchanged(self):
        os.environ["WAZUH_DEDUP_MODE"] = "alert_id"
        self.assertEqual(self.reference(self.alert), "wazuh-120301-172002")

    def run_ingestion(self, alert, responder):
        with patch.object(integration, "load_environment"):
            with patch.object(integration, "load_alert", return_value=alert):
                with patch.object(integration.requests, "post", side_effect=responder):
                    with redirect_stdout(io.StringIO()):
                        return integration.main()

    def test_replay_and_new_evidence_ingestion(self):
        stored = {}

        def respond(endpoint, headers, json, timeout):
            reference = json["sourceRef"]
            if reference in stored:
                body = {
                    "type": "CreateError",
                    "message": f"Alert external:wazuh:{reference} already exists in organisation soc-lab",
                }
                return types.SimpleNamespace(status_code=400, text=str(body), json=lambda: body)
            stored[reference] = copy.deepcopy(json)
            return types.SimpleNamespace(status_code=201)

        changed = copy.deepcopy(self.alert)
        changed["id"] = "TEST-NOUVELLE-PREUVE-2"
        changed["win"]["eventdata"]["image"] = r"C:\Windows\Temp\preuve-nouvelle.exe"
        changed["full_log"] = "TEST: new process on the same endpoint"
        for alert in [self.alert, self.alert, changed, changed]:
            self.assertEqual(self.run_ingestion(alert, respond), 0)
        self.assertEqual(len(stored), 2)
        new_payload = stored[self.reference(changed)]
        self.assertIn(changed["win"]["eventdata"]["image"], {
            observable["data"] for observable in new_payload["observables"]
        })

    def test_unrelated_400_is_an_error(self):
        body = {"type": "CreateError", "message": "Invalid alert"}
        response = types.SimpleNamespace(status_code=400, text=str(body), json=lambda: body)
        self.assertEqual(self.run_ingestion(self.alert, lambda *args, **kwargs: response), 1)

    def test_409_remains_a_duplicate(self):
        response = types.SimpleNamespace(status_code=409)
        self.assertEqual(self.run_ingestion(self.alert, lambda *args, **kwargs: response), 0)


if __name__ == "__main__":
    unittest.main()