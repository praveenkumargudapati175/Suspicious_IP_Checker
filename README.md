# Suspicious IP Checker

A defensive Python dashboard for checking IP reputation against a local CSV and,
optionally, AbuseIPDB. It can poll appended lines from server logs you own or
are authorized to inspect, save results to SQLite, and send optional email
alerts.

This tool reports indicators; it does not block traffic or guarantee that an
address is safe. The included local indicators are documentation-only
demonstration addresses reserved for examples. They are not verified threats.

## Requirements

- Windows 10/11
- Python 3.10 or later
- An AbuseIPDB API key only for live external reputation queries
- SMTP credentials only for email notifications

## Install and run on Windows

Open PowerShell in the project folder:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
streamlit run app.py
```

If PowerShell blocks activation, run this for the current PowerShell process,
then activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Streamlit prints a local URL, usually `http://localhost:8501`.

The app runs locally in development mode without Google, AbuseIPDB, or SMTP
credentials. The local threat list and safe demo check work offline. **Do not
deploy with `APP_ENV=development`: it deliberately bypasses sign-in for local
development.** Streamlit Community Cloud uses a production setting and fails
closed unless Google sign-in and its allowed-user list are configured.

## Optional configuration

Edit `.env` after copying `.env.example`:

```dotenv
ABUSEIPDB_API_KEY=your_private_api_key
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_email_app_password
ALERT_FROM=your_email@gmail.com
ALERT_TO=recipient@example.com
```

An AbuseIPDB key is optional. Without one, local indicators still work, but a
public address has no live reputation result. To obtain a key, create your own
[AbuseIPDB account and API key](https://www.abuseipdb.com/account/api). Add it
as `ABUSEIPDB_API_KEY` in your local `.env`, restart the app, then choose
**Google Public DNS** or **Cloudflare DNS** under **IP reputation** and select
**Check reputation**. Those are public service examples, not known-malicious
test IPs. Never paste credentials into the app, source code, GitHub,
screenshots, or chat.
Restart Streamlit after changing `.env`. Keep `.env` private; it is excluded
from Git by `.gitignore`.

When deployed to Streamlit Community Cloud, configure
`ABUSEIPDB_API_KEY` under the app's **Settings → Secrets** instead of uploading
`.env`. Globally routable IPs checked with a key are disclosed to AbuseIPDB.
Private, reserved, and otherwise non-global addresses are never sent to that
provider. Check its current terms, account quotas, and privacy policy first.

Email is sent over SMTP STARTTLS only when every email setting is configured
and a check is flagged suspicious. Delivery failures appear in the dashboard.

## Using the dashboard

### IP Reputation Check

Open **IP reputation**, choose an example, and select **Check reputation**:

| Example | Purpose | Needs an API key? |
| --- | --- | --- |
| `198.51.100.23` | Reserved documentation address in the demo CSV; reliably tests a local suspicious match without contacting an external service. | No |
| `8.8.8.8` | Google Public DNS; demonstrates a live public-IP lookup when configured. It is not a known-malicious test address. | Yes, for a live result |
| `1.1.1.1` | Cloudflare DNS; another public-IP lookup example, not a known-malicious test address. | Yes, for a live result |
| An address from your authorized logs | Investigate an address you are permitted to check. | Optional; public lookups disclose it to AbuseIPDB |

The dashboard checks its local CSV first and queries AbuseIPDB only for
globally routable addresses when a key is configured. An API confidence score
of 50 or higher is flagged by default; adjust `DEFAULT_THRESHOLD` in
`checker.py` if your policy requires another threshold. A low score is not
proof an address is safe. API limits and data availability vary by account and
provider.

### Bulk investigation

Use **Bulk investigation** to paste up to 25 unique IPv4 or IPv6 addresses,
separated by lines, spaces, or commas. Duplicates are removed and invalid
entries are listed rather than checked. Bulk checks use the local list by
default. Live AbuseIPDB lookups require an explicit opt-in and a configured API
key; public addresses sent to the service are disclosed to that provider.
Results are recorded in history and can be downloaded as CSV.

### Live Log Monitor

Select a log path and enable **Monitor automatically** to check for appended
lines every five seconds while the dashboard session is open. You can also
click **Scan new log lines** for a one-time scan. The scanner reads new bytes
after the previous scan in this browser session, extracts deduplicated valid
IPv4 addresses (including private and reserved addresses), checks them against
the local list, and records events. Only globally routable addresses can be
sent to AbuseIPDB, and only when an API key is configured. Use this only with
logs you own or are authorized to inspect.

To append the safe, documentation-reserved demo IP `198.51.100.23` to the sample
log, run:

```powershell
python create_sample_log.py
```

With the default local indicator CSV, the demo address is flagged as
suspicious locally and is never sent to an external provider. Start monitoring
or click **Scan new log lines** to see the dashboard alert. Monitoring stops
when the dashboard session closes; this prototype does not run as a background
process or Windows service. Log formats are not interpreted beyond IPv4
extraction.

### Event History

Results are stored in `data/events.db`; the Activity workspace supports status
and IP filtering and filtered CSV downloads. The database is created
automatically and is ignored by Git. The Threat intelligence workspace lists
and searches the local indicators used for matching.

## Google sign-in and Streamlit Community Cloud

Sign-in uses Streamlit's built-in OpenID Connect support with Google. The app
requires both a working Google identity configuration and a non-empty
`allowed_emails` list before it opens the dashboard. An account that is not on
that list is denied access. Do not put Google credentials in `.env.example` or
commit them to Git.

1. Create a GitHub repository and deploy its root `app.py` with Streamlit
   Community Cloud. Choose the app's public subdomain and note its URL.
2. In [Google Cloud Console](https://console.cloud.google.com/), create a
   project and configure Google Auth Platform / OAuth consent. While the app
   publishing status is **Testing**, add your Google account under **Test
   users**.
3. Create an OAuth client with application type **Web application**. Add the
   deployed callback URL to **Authorized redirect URIs**:
   `https://YOUR-APP.streamlit.app/oauth2callback`. For local sign-in tests, also
   add `http://localhost:8501/oauth2callback` (or the actual local app port).
4. Copy [`.streamlit/secrets.toml.example`](.streamlit/secrets.toml.example)
   into **Streamlit Community Cloud → App settings → Secrets** and replace
   every Google placeholder. Set `redirect_uri` to the exact deployed callback
   URL. Set `allowed_emails` to the Google account(s) permitted to use this
   dashboard.
5. Keep `environment = "production"` in the `[app]` section. Add the optional
   top-level `ABUSEIPDB_API_KEY` if live lookups are wanted. Add every required
   top-level `SMTP_*` / `ALERT_*` value for email alerts. Do not publish the
   real secret values.

**Log access when hosted:** a Streamlit Cloud app runs on a remote host and
cannot read a path on your Windows laptop or private server. The log monitor
reads paths on the machine running Streamlit. Run the app locally to monitor
local log files; for hosted monitoring, first connect an authorized,
cloud-accessible log source with appropriate access controls. Do not expose a
log file publicly just to make it reachable.

**Cloud storage:** Streamlit Community Cloud's local filesystem and this
prototype's SQLite history are not durable storage. An app restart or redeploy
can discard events. Use an appropriately secured persistent database before
relying on hosted event retention.

To run locally, copy `.env.example` to `.env`, keep `APP_ENV=development`, and
run `streamlit run app.py`. This explicit local-only mode bypasses Google sign
in so the dashboard can be tested before Google credentials are created. Do
not use development mode for a public deployment. A sample secrets template
is documentation only; never rename it to `secrets.toml` and commit it.

## Local threat list

Edit `data/threat_ips.csv` with the columns `ip_address`, `label`, and `score`.
Entries are validated as IP addresses when loaded. Use trusted, current
indicators and document their source and expiry in your own operational
process.

## Tests

From the project folder:

```powershell
python -m unittest discover -s tests -v
```

The tests cover local matches, invalid inputs, API threshold behavior,
non-public address privacy, API failures, incremental log reading, IPv4
extraction, and SQLite event storage. API tests are mocked and do not call the
live service; no API key or SMTP credentials are needed to run them.

## Project materials

- [Project report](docs/Project_Report.md)
- [PowerPoint presentation](docs/Suspicious_IP_Checker.pptx)
- [Presentation outline](docs/Presentation.md)
- [System flowchart](docs/flowchart.svg)

## Limitations

- Local development mode intentionally bypasses sign-in; production mode must
  use Google OIDC with an explicit allowed-email list.
- Deploying to Streamlit Community Cloud requires a GitHub repository and
  configured OAuth/API/SMTP secrets; the app cannot be published without
  those account-specific steps.
- Reputation data can be incomplete, stale, or incorrect; a clean result is not
  proof of safety.
- The demo CSV contains reserved example IPs, not confirmed malicious hosts.
- API quotas and availability depend on AbuseIPDB and your account.
- Log monitoring polls every five seconds only while the dashboard is open and
  extracts IPv4 addresses only.
- Email depends on provider configuration and network availability.
- No automatic blocking or remediation is performed.
