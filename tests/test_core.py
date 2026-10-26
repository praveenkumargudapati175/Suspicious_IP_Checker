import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from checker import check_ip, load_threat_ips, parse_ip_batch
from log_monitor import (
    extract_ipv4_addresses,
    log_file_identity,
    read_new_lines,
)
from storage import fetch_events, record_event


PROJECT_DIR = Path(__file__).resolve().parents[1]


class CheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.indicators = load_threat_ips(PROJECT_DIR / "data" / "threat_ips.csv")

    def test_local_demo_indicator_is_flagged(self) -> None:
        result = check_ip("198.51.100.23", indicators=self.indicators)
        self.assertEqual(result.status, "SUSPICIOUS")
        self.assertTrue(result.local_match)
        self.assertEqual(result.local_score, 85)

    def test_invalid_ip_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            check_ip("999.1.1.1", indicators=self.indicators)

    def test_private_address_is_never_sent_to_external_api(self) -> None:
        with patch("checker.requests.get") as get:
            result = check_ip(
                "192.168.1.5", indicators=self.indicators, api_key="test-key"
            )
        get.assert_not_called()
        self.assertEqual(result.api_status, "skipped_non_public")

    @patch("checker.requests.get")
    def test_api_threshold_flags_ip(self, get: Mock) -> None:
        response = Mock()
        response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 75,
                "totalReports": 4,
                "countryCode": "US",
                "isp": "Example ISP",
            }
        }
        get.return_value = response
        result = check_ip("8.8.8.8", indicators={}, api_key="test-key")
        self.assertEqual(result.status, "SUSPICIOUS")
        self.assertEqual(result.abuse_score, 75)

    def test_api_failure_is_visible_and_not_a_clean_result(self) -> None:
        from requests import RequestException

        with patch(
            "checker.requests.get", side_effect=RequestException("service unavailable")
        ):
            result = check_ip("8.8.8.8", indicators={}, api_key="test-key")
        self.assertEqual(result.status, "UNKNOWN / API UNAVAILABLE")
        self.assertIn("service unavailable", result.message)

    @patch("checker.requests.get")
    def test_malformed_api_response_is_not_reported_as_clean(self, get: Mock) -> None:
        response = Mock()
        response.json.return_value = {"data": {}}
        get.return_value = response
        result = check_ip("8.8.8.8", indicators={}, api_key="test-key")
        self.assertEqual(result.status, "UNKNOWN / API UNAVAILABLE")
        self.assertEqual(result.api_status, "unavailable")

    def test_parse_ip_batch_normalizes_and_deduplicates_addresses(self) -> None:
        valid, invalid = parse_ip_batch(
            "8.8.8.8, 2001:4860:4860::8888\n8.8.8.8 bad-ip"
        )
        self.assertEqual(valid, ["8.8.8.8", "2001:4860:4860::8888"])
        self.assertEqual(invalid, ["bad-ip"])

    def test_parse_ip_batch_rejects_batches_over_limit(self) -> None:
        with self.assertRaisesRegex(ValueError, "Batch limit is 1"):
            parse_ip_batch("8.8.8.8 1.1.1.1", limit=1)


class LogMonitorTests(unittest.TestCase):
    def test_extracts_valid_ipv4_including_non_public_and_deduplicates(self) -> None:
        found = extract_ipv4_addresses(
            [
                "client=8.8.8.8 peer=8.8.8.8 private=192.168.1.2 "
                "demo=198.51.100.23 invalid=999.1.1.1"
            ]
        )
        self.assertEqual(found, ["8.8.8.8", "192.168.1.2", "198.51.100.23"])

    def test_reads_only_new_bytes_and_resets_after_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "server.log"
            path.write_text("first\n", encoding="utf-8")
            lines, offset = read_new_lines(path, 0)
            self.assertEqual(lines, ["first"])
            with path.open("a", encoding="utf-8") as file:
                file.write("second\n")
            lines, offset = read_new_lines(path, offset)
            self.assertEqual(lines, ["second"])
            path.write_text("new\n", encoding="utf-8")
            lines, _ = read_new_lines(path, offset)
            self.assertEqual(lines, ["new"])

    def test_file_identity_changes_after_log_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "server.log"
            replacement = Path(temporary) / "replacement.log"
            path.write_text("old log\n", encoding="utf-8")
            replacement.write_text("replacement log\n", encoding="utf-8")
            previous_identity = log_file_identity(path)
            replacement.replace(path)
            self.assertNotEqual(previous_identity, log_file_identity(path))


class StorageTests(unittest.TestCase):
    def test_event_round_trip(self) -> None:
        result = {
            "ip_address": "8.8.8.8",
            "status": "NO REPUTATION FLAG",
            "local_match": False,
            "local_label": "",
            "local_score": None,
            "api_status": "available",
            "abuse_score": 0,
            "reports": 0,
            "country": "US",
            "isp": "Example",
            "message": "Check complete",
        }
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "events.db"
            record_event(database, result)
            events = fetch_events(database)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["ip_address"], result["ip_address"])
        self.assertEqual(events[0]["status"], result["status"])


if __name__ == "__main__":
    unittest.main()
