# Presentation: Suspicious IP Checker

## Slide 1 — Title

**Suspicious IP Checker Using Threat Intelligence and Server Log Monitoring**

Python, Streamlit, SQLite, AbuseIPDB (optional)

## Slide 2 — Problem

- Reviewing IP addresses in server logs manually is time-consuming.
- Threat feeds can be incomplete or temporarily unavailable.
- Operators need a reviewable history and clear uncertainty signals.

## Slide 3 — Project objectives

- Combine local indicators and optional external reputation.
- Support single-IP and capped 25-address batch investigations, with explicit
  opt-in before sending public addresses to AbuseIPDB.
- Scan authorized server logs on demand or poll them every five seconds while
  the dashboard is open.
- Save results and provide dashboard and email notifications.
- Avoid automatically blocking traffic.

## Slide 4 — Technology stack

- Python 3.10+
- Streamlit dashboard
- Google OpenID Connect sign-in with an authorized-email allowlist in
  production
- Requests for optional AbuseIPDB API calls
- SQLite for event history
- SMTP STARTTLS for optional email
- CSV for local indicators

## Slide 5 — System architecture

The dashboard accepts an IP or log path. The checker validates and matches
addresses, optionally queries AbuseIPDB, applies a threshold, and returns a
status. Results are stored in SQLite and suspicious findings can trigger
email.

## Slide 6 — Detection logic

1. Validate and normalize IP.
2. Check the local CSV.
3. Query the external provider only for public IPs when configured.
4. Flag local matches or API scores at or above 50.
5. Store the result and notify if configured.

## Slide 7 — Log monitoring

- Manual scan or five-second polling of appended bytes.
- Extracts and deduplicates IPv4 addresses, including local-only addresses.
- Checks each extracted address through the same reputation workflow.
- Non-public addresses are checked locally and never sent to the API.
- Polling stops when the dashboard session closes; no Windows service is used.

## Slide 8 — Dashboard and event history

- Reputation result and supporting fields.
- Seven workspaces: Overview, IP reputation, Bulk investigation, Live log
  monitor, Threat intelligence, Activity, and Settings & deployment.
- Searchable local indicators and status/IP filters for event history.
- Recent events persisted in SQLite.
- CSV export.
- Optional SMTP alert on suspicious results.

## Slide 9 — Testing and demonstration

- Demonstration local indicators use reserved example IPs.
- Batch testing accepts valid inputs, lists invalid entries, and removes
  duplicates before checking addresses.
- Invalid IP input is rejected.
- API logic and failures are tested offline with mocks.
- Append the reserved demo indicator using `python create_sample_log.py` and
  scan it to verify a local suspicious alert.

## Slide 10 — Privacy and limitations

- Public IPs checked with API are disclosed to AbuseIPDB.
- Non-public addresses are not submitted externally.
- API data may be incomplete; clean does not mean safe.
- Demo dataset is not verified threat intelligence.
- No automatic blocking or remediation.

## Slide 11 — Conclusion and next steps

The prototype provides a transparent, human-reviewed flow from IP/log input to
reputation result and event record. Production use should add trusted current
indicators, operational monitoring, source/expiry tracking, and security review.

## Slide 12 — Google sign-in and deployment

- Production access uses Streamlit's built-in Google OIDC sign-in.
- Only Google accounts on the configured email allowlist may enter.
- Configure the OAuth redirect URI and secrets in Streamlit Community Cloud.
- Local development sign-in bypass is explicitly not for public deployment.

## Slide 13 — IP examples and API

- `198.51.100.23` is a reserved local demo indicator; no API key is needed.
- `8.8.8.8` and `1.1.1.1` demonstrate public API lookups; they are not known
  malicious examples.
- Add your own AbuseIPDB API key in private deployment secrets to run live
  checks; selected public IPs are disclosed to AbuseIPDB.
