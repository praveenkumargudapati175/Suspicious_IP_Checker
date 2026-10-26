# Suspicious IP Checker Using Threat Intelligence and Server Log Monitoring

## Abstract

The Suspicious IP Checker is a defensive monitoring prototype that combines a
local IP indicator list with optional IP reputation checks from AbuseIPDB. It
provides a seven-workspace Streamlit interface, single and capped bulk IP
checks, manual or automatic scanning of newly appended server-log lines,
SQLite event history, filtered CSV export, and optional email alerts. It is
intended for systems and logs that the operator owns or is authorized to
inspect. It reports findings but does not block traffic.

## Problem statement

Administrators need a practical way to review IP addresses appearing in their
systems and logs. Manual comparison against threat information can be slow,
while a single reputation source can be unavailable or incomplete. This
prototype combines a locally maintained list with an optional external source
and keeps a record of checks for later review.

## Objectives

1. Validate IPv4 and IPv6 inputs before assessment.
2. Match IPs against a local CSV dataset.
3. Optionally query AbuseIPDB for globally routable addresses.
4. Apply a configurable abuse-confidence threshold (default 50).
5. Scan newly appended log lines on demand or every five seconds during an
   active dashboard session, extracting valid IPv4 addresses.
6. Persist results in SQLite, show dashboard alerts, and export CSV history.
7. Send optional SMTP email alerts when an address is flagged.
8. Avoid sending non-public addresses to the external reputation provider.
9. Provide batch investigations with input validation, deduplication, and an
   explicit opt-in before disclosing public addresses to AbuseIPDB.
10. Search local indicators and filter investigation history in the dashboard.

## Architecture and components

- `app.py`: Streamlit dashboard, Google OIDC access gate, and user workflow.
- `checker.py`: IP and batch validation, local matching, AbuseIPDB integration,
  and threshold decision.
- `log_monitor.py`: Incremental byte-offset log reading and IPv4
  extraction.
- `storage.py`: SQLite schema, event persistence, and CSV export.
- `notifications.py`: Optional SMTP STARTTLS alert delivery.
- `settings.py`: Environment and Streamlit Cloud secret configuration.
- `.streamlit/secrets.toml.example`: Placeholder Google OIDC, allowlist, and
  optional provider settings; never contains real credentials.
- `data/threat_ips.csv`: Demonstration-only local indicators.
- `tests/test_core.py`: Offline unit tests.

## Detection workflow

The application validates an input address, normalizes it, and checks the local
dataset. If an API key is configured and the address is globally routable, the
application queries AbuseIPDB. Non-public addresses are checked locally only.
Bulk investigations normalize and deduplicate up to 25 addresses and list
invalid entries without checking them. They use local indicators by default;
the user must explicitly opt in before public addresses are submitted
externally.
A local match or an API confidence score at or above the configured threshold
is marked **SUSPICIOUS**. A successful API
response below threshold is **NO REPUTATION FLAG**. Without a usable API
response and without a local match, the result is **UNKNOWN / API UNAVAILABLE**.
The result is saved to SQLite. A suspicious result triggers an email only when
all SMTP settings are configured.

## Data and privacy

The CSV examples use documentation-reserved addresses and do not represent
verified malicious infrastructure. Operators must supply trusted indicators
before relying on local results. Configuring AbuseIPDB causes globally
routable IPs that are checked to be disclosed to that service. The project
skips external lookups for non-global addresses. Keep API keys and SMTP
credentials in a local `.env` file, not in source control.

The dashboard supports Google OpenID Connect using Streamlit's built-in
authentication. Production mode requires configured OAuth client settings and
an explicit allowlist of permitted Google email addresses; other users are
denied access. Local development mode bypasses sign-in only to simplify local
testing. Never deploy with `APP_ENV=development`. Streamlit Community Cloud
credentials belong in its app secrets, not in the repository.

The dashboard separates Overview, IP reputation, Bulk investigation, Live log
monitor, Threat intelligence, Activity, and Settings & deployment into distinct
workspaces. The activity view supports status/IP filtering and CSV export; the
threat-intelligence view supports local indicator search.

## Testing plan and results

The included 12-test unittest suite covers local matching, invalid addresses,
batch normalization/deduplication/limits, API threshold logic with a mocked
response, API failure handling, non-public IP privacy, incremental log reads,
IPv4 extraction, and SQLite storage. Tests do not require a live API account or
send email. The app was also smoke-tested to confirm all seven workspaces render.

Run the suite with:

```powershell
python -m unittest discover -s tests -v
```

## Limitations and future work

- Live log polling checks every five seconds only while the dashboard session
  is open; it is not a Windows service.
- The parser extracts IPv4 only and does not understand application-
  specific log formats.
- Bulk investigation is capped at 25 unique addresses per run; it is not a
  substitute for a high-volume feed processing pipeline.
- External reputation checks are subject to provider outages, quotas, and
  false positives or false negatives.
- Email delivery depends on SMTP provider settings.
- Live hosting requires a GitHub repository, a configured Google OAuth web
  client, the exact Streamlit callback URL, and app secrets.
- A hosted Streamlit app cannot read logs from the operator's Windows laptop;
  the configured log path must exist on the Streamlit host. Hosted log
  monitoring needs an explicitly authorized cloud-accessible log source.
- Streamlit Community Cloud's local filesystem is not durable storage, so the
  SQLite event database can be lost on restart or redeploy.
- No automated firewall changes or blocking are performed.
- Possible future enhancements include configurable log parsers, background
  monitoring with explicit service controls, indicator expiry/source metadata,
  and additional authorized intelligence providers.

## Conclusion

The project demonstrates a small, auditable workflow for combining local
indicators and optional external IP reputation with authorized log review. It
provides a usable dashboard and event history while making API uncertainty and
privacy implications explicit. Findings should be treated as leads for human
review, not definitive proof of malicious activity.
