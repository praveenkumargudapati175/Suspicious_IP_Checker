from __future__ import annotations

import csv
import ipaddress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import requests


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_THRESHOLD = 50


def parse_ip_batch(raw_text: str, *, limit: int = 25) -> tuple[list[str], list[str]]:
    """Normalize a newline/comma/space-separated IP batch and retain invalid tokens."""
    addresses: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()
    for token in raw_text.replace(",", " ").split():
        try:
            normalized = str(ipaddress.ip_address(token))
        except ValueError:
            invalid.append(token)
            continue
        if normalized not in seen:
            seen.add(normalized)
            addresses.append(normalized)
            if len(addresses) > limit:
                raise ValueError(f"Batch limit is {limit} unique IP addresses.")
    return addresses, invalid


@dataclass(frozen=True)
class CheckResult:
    ip_address: str
    status: str
    local_match: bool
    local_label: str
    local_score: int | None
    api_status: str
    abuse_score: int | None
    reports: int | None
    country: str
    isp: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_threat_ips(csv_path: Path) -> dict[str, dict[str, str]]:
    """Load IP indicators from the local CSV, validating each address."""
    indicators: dict[str, dict[str, str]] = {}
    with csv_path.open("r", encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            raw_ip = (row.get("ip_address") or "").strip()
            if not raw_ip:
                continue
            address = ipaddress.ip_address(raw_ip)
            indicators[str(address)] = {
                "label": (row.get("label") or "Local indicator").strip(),
                "score": (row.get("score") or "").strip(),
            }
    return indicators


def check_ip(
    raw_ip: str,
    *,
    indicators: dict[str, dict[str, str]],
    api_key: str = "",
    threshold: int = DEFAULT_THRESHOLD,
    timeout: float = 8.0,
) -> CheckResult:
    """Check one address locally and, for public IPs, optionally with AbuseIPDB."""
    address = ipaddress.ip_address(raw_ip.strip())
    normalized_ip = str(address)
    local = indicators.get(normalized_ip)
    local_score = None
    if local and local.get("score"):
        try:
            local_score = int(local["score"])
        except ValueError:
            local_score = None

    api_status = "not_configured"
    abuse_score = None
    reports = None
    country = ""
    isp = ""
    message = "No API key configured; local intelligence was checked."

    if api_key and address.is_global:
        try:
            response = requests.get(
                ABUSEIPDB_URL,
                headers={
                    "Key": api_key,
                    "Accept": "application/json",
                    "User-Agent": "Suspicious-IP-Checker/1.0",
                },
                params={"ipAddress": normalized_ip, "maxAgeInDays": 90},
                timeout=timeout,
            )
            response.raise_for_status()
            response_payload = response.json()
            if not isinstance(response_payload, dict):
                raise ValueError("AbuseIPDB returned an invalid response.")
            payload = response_payload.get("data")
            if not isinstance(payload, dict):
                raise ValueError("AbuseIPDB response did not contain reputation data.")
            if "abuseConfidenceScore" not in payload:
                raise ValueError("AbuseIPDB response is missing its confidence score.")
            abuse_score = int(payload["abuseConfidenceScore"])
            if not 0 <= abuse_score <= 100:
                raise ValueError("AbuseIPDB confidence score is outside the 0-100 range.")
            reports = int(payload.get("totalReports", 0))
            country = str(payload.get("countryCode") or "")
            isp = str(payload.get("isp") or "")
            api_status = "available"
            message = "AbuseIPDB reputation check completed."
        except (
            requests.RequestException,
            ValueError,
            TypeError,
            AttributeError,
        ) as error:
            api_status = "unavailable"
            message = f"AbuseIPDB lookup failed: {error}"
    elif api_key:
        api_status = "skipped_non_public"
        message = "External lookup skipped because the address is not globally routable."

    suspicious_by_api = (
        api_status == "available"
        and abuse_score is not None
        and abuse_score >= threshold
    )
    if local:
        status = "SUSPICIOUS"
        local_message = (
            f"Matched local indicator: {local.get('label') or 'Local indicator'}."
        )
        if api_status == "unavailable":
            message = f"{local_message} {message}"
        else:
            message = local_message
    elif suspicious_by_api:
        status = "SUSPICIOUS"
    elif api_status == "available":
        status = "NO REPUTATION FLAG"
    else:
        status = "UNKNOWN / API UNAVAILABLE"

    return CheckResult(
        ip_address=normalized_ip,
        status=status,
        local_match=local is not None,
        local_label=local.get("label", "") if local else "",
        local_score=local_score,
        api_status=api_status,
        abuse_score=abuse_score,
        reports=reports,
        country=country,
        isp=isp,
        message=message,
    )
