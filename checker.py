from __future__ import annotations

import csv
import ipaddress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import requests


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators"
DEFAULT_THRESHOLD = 50


def parse_ip_batch(raw_text: str, *, limit: int = 25) -> tuple[list[str], list[str]]:
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
    vt_malicious: int | None = None
    vt_suspicious: int | None = None
    otx_pulses: int | None = None
    sources_checked: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_threat_ips(csv_path: Path) -> dict[str, dict[str, str]]:
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
    virus_total_api_key: str = "",
    otx_api_key: str = "",
) -> CheckResult:
    """Check an IP locally and optionally against three reputation services."""

    address = ipaddress.ip_address(raw_ip.strip())
    normalized_ip = str(address)

    local = indicators.get(normalized_ip)
    local_score = None

    if local and local.get("score"):
        try:
            local_score = int(local["score"])
        except ValueError:
            pass

    abuse_score = None
    reports = None
    country = ""
    isp = ""

    vt_malicious = None
    vt_suspicious = None
    otx_pulses = None

    checked = []
    errors = []

    if not address.is_global:
        message = "External lookups skipped: this is not a globally routable IP."
        if local:
            message = f"Matched local indicator: {local.get('label', 'Local indicator')}."
        return CheckResult(
            ip_address=normalized_ip,
            status="SUSPICIOUS" if local else "UNKNOWN / API UNAVAILABLE",
            local_match=local is not None,
            local_label=local.get("label", "") if local else "",
            local_score=local_score,
            api_status="skipped_non_public",
            abuse_score=None,
            reports=None,
            country="",
            isp="",
            message=message,
        )

    # 1. AbuseIPDB
    if api_key:
        try:
            response = requests.get(
                ABUSEIPDB_URL,
                headers={
                    "Key": api_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": normalized_ip,
                    "maxAgeInDays": 90,
                },
                timeout=timeout,
            )
            response.raise_for_status()

            payload = response.json()["data"]
            abuse_score = int(payload["abuseConfidenceScore"])
            reports = int(payload.get("totalReports", 0))
            country = str(payload.get("countryCode") or "")
            isp = str(payload.get("isp") or "")

            checked.append("AbuseIPDB")

        except (requests.RequestException, ValueError, TypeError, KeyError) as error:
            errors.append(f"AbuseIPDB: {error}")

    # 2. VirusTotal
    if virus_total_api_key:
        try:
            response = requests.get(
                VIRUSTOTAL_URL + normalized_ip,
                headers={"x-apikey": virus_total_api_key},
                timeout=timeout,
            )
            response.raise_for_status()

            attributes = response.json()["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})

            vt_malicious = int(stats.get("malicious", 0))
            vt_suspicious = int(stats.get("suspicious", 0))

            checked.append("VirusTotal")

        except (requests.RequestException, ValueError, TypeError, KeyError) as error:
            errors.append(f"VirusTotal: {error}")

    # 3. AlienVault OTX
    if otx_api_key:
        try:
            version = "IPv4" if address.version == 4 else "IPv6"

            response = requests.get(
                f"{OTX_URL}/{version}/{normalized_ip}/general",
                headers={"X-OTX-API-KEY": otx_api_key},
                timeout=timeout,
            )
            response.raise_for_status()

            pulse_info = response.json().get("pulse_info", {})
            otx_pulses = int(pulse_info.get("count", 0))

            checked.append("AlienVault OTX")

        except (requests.RequestException, ValueError, TypeError, KeyError) as error:
            errors.append(f"AlienVault OTX: {error}")

    # Combine results
    suspicious_by_abuse = (
        abuse_score is not None and abuse_score >= threshold
    )
    suspicious_by_vt = (
        (vt_malicious or 0) > 0 or (vt_suspicious or 0) > 0
    )

    if local:
        status = "SUSPICIOUS"
        message = f"Matched local indicator: {local.get('label', 'Local indicator')}."

    elif suspicious_by_abuse or suspicious_by_vt:
        status = "SUSPICIOUS"
        message = "One or more reputation sources reported suspicious activity."

    elif checked:
        status = "NO REPUTATION FLAG"
        message = "No suspicious flag was returned by the sources checked."

    else:
        status = "UNKNOWN / API UNAVAILABLE"
        message = "No reputation API returned a usable result."

    if checked:
        message += " Sources checked: " + ", ".join(checked) + "."

    if errors:
        message += " Some lookups failed: " + " | ".join(errors)

    return CheckResult(
        ip_address=normalized_ip,
        status=status,
        local_match=local is not None,
        local_label=local.get("label", "") if local else "",
        local_score=local_score,
        api_status="available" if checked else (
            "unavailable" if errors else "not_configured"
        ),
        abuse_score=abuse_score,
        reports=reports,
        country=country,
        isp=isp,
        message=message,
        vt_malicious=vt_malicious,
        vt_suspicious=vt_suspicious,
        otx_pulses=otx_pulses,
        sources_checked=", ".join(checked),
    )
