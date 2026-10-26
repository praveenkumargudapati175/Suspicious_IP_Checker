from __future__ import annotations

import ipaddress
import smtplib
from collections import Counter
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

from checker import CheckResult, check_ip, load_threat_ips, parse_ip_batch
from log_monitor import extract_ipv4_addresses, log_file_identity, read_new_lines
from notifications import email_is_configured, send_alert
from settings import get_section, get_setting
from storage import export_events_csv, fetch_events, record_event


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_LOG = BASE_DIR / "logs" / "sample_server.log"
DATABASE_PATH = DATA_DIR / "events.db"
THREAT_LIST = DATA_DIR / "threat_ips.csv"
IP_EXAMPLES = {
    "Enter a custom IP": "",
    "Safe local match - 198.51.100.23 (no API call)": "198.51.100.23",
    "Google Public DNS - 8.8.8.8 (public API lookup)": "8.8.8.8",
    "Cloudflare DNS - 1.1.1.1 (public API lookup)": "1.1.1.1",
}
load_dotenv(BASE_DIR / ".env")

st.set_page_config(page_title="Signal | IP Intelligence", page_icon="S", layout="wide")

st.markdown(
    """
    <style>
    :root { color-scheme: light; }
    [data-testid="stAppViewContainer"] { background: #f4f7fb; }
    [data-testid="stHeader"] { background: rgba(244,247,251,.88); }
    .block-container { max-width: 1440px; padding-top: 1.5rem; padding-bottom: 3rem; }
    [data-testid="stSidebar"] { background: #101b30; }
    [data-testid="stSidebar"] * { color: #e8eef8; }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color: #a9bad2; }
    [data-testid="stMetric"] {
        background: #fff; padding: 1.05rem 1.2rem; border: 1px solid #e6ebf2;
        border-radius: 16px; box-shadow: 0 5px 18px rgba(22,43,77,.045);
    }
    [data-testid="stMetricLabel"] { color: #60718a; }
    [data-testid="stMetricValue"] { color: #17243a; }
    div.stButton > button[kind="primary"] {
        background: linear-gradient(110deg,#245ce5,#1679cf);
        border: 0; border-radius: 10px; min-height: 2.8rem;
    }
    div.stButton > button { border-radius: 10px; }
    [data-testid="stSidebar"] [role="radiogroup"] { gap: .3rem; }
    [data-testid="stSidebar"] [role="radiogroup"] label {
        padding: .48rem .65rem; border-radius: 10px; transition: background .15s ease;
    }
    [data-testid="stSidebar"] [role="radiogroup"] label:hover { background: #1b2a43; }
    [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
        background: #20395d; border: 1px solid #315785;
    }
    .signal-hero {
        background: radial-gradient(ellipse at 85% 15%,rgba(53,124,247,.48),transparent 34%),
                    linear-gradient(118deg,#101b30 0%,#18335c 62%,#145d77 100%);
        color: #f7faff; border-radius: 24px; padding: 2rem 2.15rem;
        margin: .25rem 0 1.65rem; box-shadow: 0 18px 46px rgba(18,40,78,.17);
    }
    .signal-hero h1 { color: white; font-size: clamp(2rem,4vw,3rem); margin: .4rem 0 .45rem; }
    .signal-hero p { color: #d6e4f7; font-size: 1.02rem; max-width: 760px; }
    .signal-eyebrow { text-transform: uppercase; letter-spacing: .17em; font-size: .72rem;
        font-weight: 750; color: #8ed9ff; }
    .signal-note {
        padding: 1rem 1.1rem; border: 1px solid #dce6f2; border-radius: 14px;
        background: #fff; color: #52647e; font-size: .93rem;
    }
    .signal-card {
        padding: 1.15rem 1.25rem; border: 1px solid #e6ebf2; border-radius: 16px;
        background: #fff; min-height: 130px;
    }
    .signal-card h3 { margin: .15rem 0 .4rem; color: #17243a; }
    .signal-card p { margin: 0; color: #60718a; }
    .signal-section-kicker {
        color: #4774ac; font-size: .73rem; font-weight: 750;
        letter-spacing: .14em; text-transform: uppercase; margin-bottom: .2rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def evaluate_ip(raw_ip: str, *, allow_external: bool = True) -> CheckResult:
    address = ipaddress.ip_address(raw_ip.strip())
    return check_ip(
        str(address),
        indicators=load_threat_ips(THREAT_LIST),
        api_key=get_setting("ABUSEIPDB_API_KEY") if allow_external else "",
    )


def save_and_alert(result: CheckResult) -> None:
    result_data = result.to_dict()
    record_event(DATABASE_PATH, result_data)
    if result.status == "SUSPICIOUS" and email_is_configured():
        try:
            send_alert(result_data)
            st.success("Email alert sent.")
        except (OSError, ValueError) as error:
            st.error(f"Email alert could not be sent: {error}")
        except smtplib.SMTPException as error:
            st.error(f"Email provider rejected the alert: {error}")


def show_result(result: CheckResult) -> None:
    if result.status == "SUSPICIOUS":
        st.error(f"🚨 {result.status}")
    elif result.status == "NO REPUTATION FLAG":
        st.success(result.status)
    else:
        st.warning(result.status)
    st.write(result.message)

    details = {
        "IP address": result.ip_address,
        "Local indicator match": "Yes" if result.local_match else "No",
        "Local label": result.local_label or "—",
        "Local score": (
            str(result.local_score) if result.local_score is not None else "—"
        ),
        "AbuseIPDB status": result.api_status,
        "Abuse confidence score": (
            str(result.abuse_score) if result.abuse_score is not None else "—"
        ),
        "Reports": str(result.reports) if result.reports is not None else "—",
        "Country": result.country or "—",
        "ISP": result.isp or "—",
    }
    st.dataframe(
        [{"Field": key, "Result": value} for key, value in details.items()],
        hide_index=True,
        width="stretch",
    )


def apply_ip_example() -> None:
    st.session_state["ip_address_input"] = IP_EXAMPLES[
        st.session_state["ip_example"]
    ]


def navigate_to(page: str) -> None:
    st.session_state["active_page"] = page


def google_auth_status() -> tuple[str, str | None]:
    auth = get_section("auth")
    app_settings = get_section("app")
    required = (
        "client_id",
        "client_secret",
        "redirect_uri",
        "cookie_secret",
        "server_metadata_url",
    )
    allowed_emails = app_settings.get("allowed_emails", [])
    if (
        all(str(auth.get(key, "")).strip() for key in required)
        and isinstance(allowed_emails, list)
        and allowed_emails
    ):
        if not st.user.is_logged_in:
            st.title("Welcome to Signal")
            st.write("Sign in with your authorized Google account to open the dashboard.")
            st.button("Continue with Google", type="primary", on_click=st.login)
            st.stop()

        email = str(st.user.get("email", "")).strip().lower()
        permitted = {str(value).strip().lower() for value in allowed_emails}
        if email not in permitted:
            st.error("This Google account is not on the dashboard's authorized-user list.")
            st.stop()
        return "secure", email

    if get_setting("APP_ENV").strip().lower() == "development":
        return "development", None

    st.title("Google sign-in needs configuration")
    st.error(
        "Dashboard access is locked. Configure the Google OIDC values and an "
        "authorized email allowlist in Streamlit secrets before deployment."
    )
    st.stop()


@st.fragment(run_every="5s")
def show_log_monitor(log_path_text: str, monitor_enabled: bool) -> None:
    scan = st.button("Scan new log lines", type="primary")
    if not monitor_enabled and not scan:
        st.info("Start live monitoring or run a one-time scan.")
        return

    log_path = Path(log_path_text).expanduser()
    try:
        if not log_path.is_file():
            raise FileNotFoundError(f"Log file not found: {log_path}")
        resolved_path = log_path.resolve()
        cursor_key = f"log_offset:{resolved_path}"
        identity_key = f"log_identity:{resolved_path}"
        identity = log_file_identity(log_path)
        if st.session_state.get(identity_key) != identity:
            st.session_state[cursor_key] = 0
            st.session_state[identity_key] = identity
        offset = int(st.session_state.get(cursor_key, 0))
        lines, new_offset = read_new_lines(log_path, offset)
        st.session_state[cursor_key] = new_offset
        addresses = extract_ipv4_addresses(lines)
        st.write(
            f"Read **{len(lines)}** new line(s); found **{len(addresses)}** "
            "unique IPv4 address(es)."
        )
        if not addresses:
            st.info("No new IPv4 addresses found.")
        for address in addresses:
            result = evaluate_ip(address)
            save_and_alert(result)
            with st.expander(f"{address} — {result.status}", expanded=True):
                show_result(result)
    except (OSError, ValueError) as error:
        st.error(f"Could not scan the log file: {error}")


auth_mode, signed_in_email = google_auth_status()

with st.sidebar:
    st.markdown(
        '<div style="padding:.45rem .1rem 1.4rem">'
        '<span style="display:inline-block;background:#2867e8;border-radius:10px;'
        'padding:.45rem .6rem;font-weight:800;color:white;margin-right:.55rem">S</span>'
        '<span style="font-weight:800;font-size:1.22rem;color:white">SIGNAL</span>'
        '<div style="font-size:.78rem;color:#9fb3ce;margin:.45rem 0 0 2.85rem">'
        'IP intelligence workspace</div></div>',
        unsafe_allow_html=True,
    )
    st.caption("NAVIGATION")
    current_page = st.radio(
        "Workspace",
        [
            "Overview",
            "IP reputation",
            "Bulk investigation",
            "Live log monitor",
            "Threat intelligence",
            "Activity",
            "Settings & deployment",
        ],
        format_func=lambda page: {
            "Overview": "◈  Overview",
            "IP reputation": "⌕  IP reputation",
            "Bulk investigation": "▦  Bulk investigation",
            "Live log monitor": "◉  Live log monitor",
            "Threat intelligence": "◇  Threat intelligence",
            "Activity": "↗  Activity",
            "Settings & deployment": "⚙  Settings & deployment",
        }[page],
        key="active_page",
        label_visibility="collapsed",
    )
    st.markdown("---")
    st.caption("SESSION")
    if signed_in_email:
        st.write(f"**{signed_in_email}**")
        st.button("Sign out", on_click=st.logout, use_container_width=True)
    else:
        st.info("Local development session")
    st.markdown("---")
    st.caption("DATA SOURCES")
    st.write("Local threat list")
    st.write(
        "AbuseIPDB: connected"
        if get_setting("ABUSEIPDB_API_KEY")
        else "AbuseIPDB: not configured"
    )
    st.markdown("---")
    st.caption("Only check addresses and logs you are authorized to inspect.")

events = fetch_events(DATABASE_PATH)
suspicious_count = sum(event["status"] == "SUSPICIOUS" for event in events)
api_count = sum(event["api_status"] == "available" for event in events)
status_counts = Counter(event["status"] for event in events)

page_content = {
    "Overview": (
        "Threat intelligence · log monitoring · response",
        "See the signal.<br>Understand the risk.",
        "Your IP security workspace for reputation checks, authorized server-log "
        "monitoring, and reviewable investigation history.",
    ),
    "IP reputation": (
        "INVESTIGATIONS · IP REPUTATION",
        "Know what an address<br>is telling you.",
        "Check an IP against local indicators and, when configured, live reputation data.",
    ),
    "Bulk investigation": (
        "INVESTIGATIONS · BATCH CHECKS",
        "Review addresses<br>at your pace.",
        "Validate and investigate a small, deduplicated batch with transparent privacy controls.",
    ),
    "Live log monitor": (
        "MONITORING · AUTHORIZED LOGS",
        "Watch your logs.<br>Follow the signal.",
        "Scan new entries from a server log you own or are authorized to monitor.",
    ),
    "Threat intelligence": (
        "INTELLIGENCE · LOCAL INDICATORS",
        "Know what powers<br>your findings.",
        "Search and review the local indicator list used by every check.",
    ),
    "Activity": (
        "INVESTIGATIONS · EVENT HISTORY",
        "Every check.<br>One clear timeline.",
        "Filter recent investigation results and export the evidence you need.",
    ),
    "Settings & deployment": (
        "WORKSPACE · CONFIGURATION",
        "Your workspace,<br>your controls.",
        "Review connected services, deployment requirements, and data privacy.",
    ),
}
page_eyebrow, page_title, page_description = page_content[current_page]

st.markdown(
    f"""
    <section class="signal-hero">
      <div class="signal-eyebrow">{page_eyebrow}</div>
      <h1>{page_title}</h1>
      <p>{page_description}</p>
    </section>
    """,
    unsafe_allow_html=True,
)

if auth_mode == "development":
    st.warning(
        "Development access only. Google sign-in is not configured. "
        "Configure OIDC and the authorized-email allowlist before deployment."
    )
if not get_setting("ABUSEIPDB_API_KEY"):
    st.info(
        "Local matching is ready. Add your own AbuseIPDB API key to enable live "
        "lookups for globally routable IPs."
    )

if current_page == "Overview":
    st.subheader("Security overview")
    metric_a, metric_b, metric_c, metric_d = st.columns(4)
    metric_a.metric("Checks recorded", len(events))
    metric_b.metric("Flagged suspicious", suspicious_count)
    metric_c.metric("API lookups", api_count)
    metric_d.metric("Local indicators", len(load_threat_ips(THREAT_LIST)))

    left, right = st.columns([1.2, 1])
    with left:
        st.markdown("#### Recent investigations")
        if events:
            recent_columns = [
                "created_at",
                "ip_address",
                "status",
                "api_status",
                "abuse_score",
            ]
            st.dataframe(
                [{key: event[key] for key in recent_columns} for event in events[:8]],
                hide_index=True,
                width="stretch",
            )
        else:
            st.markdown(
                '<div class="signal-note">No checks yet. Try the safe local '
                'example or make a live API lookup from <b>IP reputation</b>.</div>',
                unsafe_allow_html=True,
            )
    with right:
        st.markdown("#### Findings by status")
        if status_counts:
            st.bar_chart(dict(status_counts), horizontal=True)
        else:
            st.markdown(
                '<div class="signal-note">Your activity summary will appear '
                "here after the first check.</div>",
                unsafe_allow_html=True,
            )

    st.markdown("#### Start here")
    card_a, card_b, card_c = st.columns(3)
    with card_a:
        st.markdown(
            '<div class="signal-card"><h3>01 · Check an address</h3>'
            '<p>Inspect local matches and, optionally, live public-IP reputation.</p></div>',
            unsafe_allow_html=True,
        )
    with card_b:
        st.markdown(
            '<div class="signal-card"><h3>02 · Monitor your logs</h3>'
            '<p>Scan appended IPv4 addresses from a log file you are authorized to read.</p></div>',
            unsafe_allow_html=True,
        )
    with card_c:
        st.markdown(
            '<div class="signal-card"><h3>03 · Review evidence</h3>'
            '<p>Open an event for reputation details, then export the history as CSV.</p></div>',
            unsafe_allow_html=True,
        )
    action_a, action_b, action_c = st.columns(3)
    with action_a:
        st.button(
            "Open IP reputation",
            key="overview_open_reputation",
            on_click=navigate_to,
            args=("IP reputation",),
            use_container_width=True,
        )
    with action_b:
        st.button(
            "Open log monitor",
            key="overview_open_monitor",
            on_click=navigate_to,
            args=("Live log monitor",),
            use_container_width=True,
        )
    with action_c:
        st.button(
            "Review activity",
            key="overview_open_activity",
            on_click=navigate_to,
            args=("Activity",),
            use_container_width=True,
        )

if current_page == "IP reputation":
    st.subheader("IP reputation lookup")
    st.caption(
        "Choose a safe demo or a public DNS example. Public example checks are "
        "sent to AbuseIPDB only when you configure your own API key."
    )
    st.session_state.setdefault(
        "ip_address_input",
        IP_EXAMPLES[st.session_state.get("ip_example", "Enter a custom IP")],
    )
    st.selectbox(
        "Try an example",
        list(IP_EXAMPLES),
        key="ip_example",
        on_change=apply_ip_example,
    )
    raw_ip = st.text_input(
        "IPv4 or IPv6 address",
        placeholder="For example: 198.51.100.23",
        key="ip_address_input",
    )
    with st.expander("What do these examples do?"):
        st.markdown(
            "- **198.51.100.23** is a documentation-reserved demo indicator in "
            "the local CSV. It produces a predictable local match and is not sent "
            "to AbuseIPDB.\n"
            "- **8.8.8.8** and **1.1.1.1** are public DNS resolver addresses, "
            "not known malicious examples. With an API key, a lookup discloses "
            "the selected public IP to AbuseIPDB.\n"
            "- Without an API key, public examples show unknown reputation; "
            "no external lookup is performed."
        )
    if st.button("Check reputation", type="primary"):
        try:
            result = evaluate_ip(raw_ip)
            save_and_alert(result)
            show_result(result)
        except ValueError as error:
            st.error(f"Enter a valid IP address: {error}")

if current_page == "Bulk investigation":
    st.subheader("Bulk IP investigation")
    st.caption(
        "Check up to 25 unique addresses at once. Addresses are checked against "
        "your local indicator list first."
    )
    bulk_input = st.text_area(
        "Paste IP addresses",
        placeholder="One address per line, or separate addresses with commas",
        height=150,
        key="bulk_ip_input",
    )
    api_configured = bool(get_setting("ABUSEIPDB_API_KEY"))
    allow_bulk_external = st.checkbox(
        "I authorize sending globally routable addresses to AbuseIPDB for live reputation checks",
        disabled=not api_configured,
        help=(
            "Only enable this if you understand that each unique public address "
            "may be disclosed to AbuseIPDB."
        ),
    )
    if not api_configured:
        st.info("Add an AbuseIPDB API key to enable live checks. Bulk local checks still work.")

    if st.button("Investigate batch", type="primary"):
        st.session_state["bulk_results"] = []
        try:
            batch_addresses, invalid_addresses = parse_ip_batch(bulk_input)
            if not batch_addresses and not invalid_addresses:
                st.warning("Enter at least one IP address.")
            else:
                if invalid_addresses:
                    st.warning(
                        "Skipped invalid entries: " + ", ".join(invalid_addresses)
                    )
                results = []
                for address in batch_addresses:
                    result = evaluate_ip(
                        address,
                        allow_external=allow_bulk_external,
                    )
                    save_and_alert(result)
                    results.append(result.to_dict())
                st.session_state["bulk_results"] = results
                if not results:
                    st.info("No valid IP addresses to investigate.")
        except ValueError as error:
            st.error(str(error))

    batch_results = st.session_state.get("bulk_results", [])
    if batch_results:
        st.dataframe(batch_results, hide_index=True, width="stretch")
        st.download_button(
            "Download batch results",
            data=export_events_csv(batch_results),
            file_name="ip_investigation_batch.csv",
            mime="text/csv",
        )

if current_page == "Live log monitor":
    st.subheader("Authorized server-log monitoring")
    st.markdown(
        '<div class="signal-note">Choose a log file you own or are authorized '
        "to inspect. Automatic scans read appended data every five seconds while "
        "this dashboard session stays open. The path must exist on the computer "
        "running Streamlit; a Streamlit Cloud app cannot read files on your "
        "Windows laptop.</div>",
        unsafe_allow_html=True,
    )
    log_path_text = st.text_input(
        "Log file path",
        value=str(DEFAULT_LOG),
        help="Windows example: C:\\Logs\\server.log",
    )
    monitor_enabled = st.checkbox(
        "Monitor automatically every 5 seconds",
        help="Disable to pause automatic polling; you can still run one-time scans.",
    )
    show_log_monitor(log_path_text, monitor_enabled)
    st.caption(
        "Only IPv4 addresses are extracted. Non-public addresses are checked "
        "locally; globally routable addresses may be sent to AbuseIPDB if configured."
    )

if current_page == "Threat intelligence":
    st.subheader("Local threat intelligence")
    st.caption(
        "Review the local indicators used in every investigation. The bundled "
        "entries are reserved documentation examples, not verified threats."
    )
    indicators = load_threat_ips(THREAT_LIST)
    metric_x, metric_y = st.columns(2)
    metric_x.metric("Indicators loaded", len(indicators))
    metric_y.metric("Source", "Local CSV")
    indicator_query = st.text_input(
        "Search indicators",
        placeholder="Search by IP address or label",
        key="indicator_query",
    ).casefold()
    indicator_rows = [
        {
            "IP address": address,
            "Label": details["label"],
            "Score": details["score"] or "—",
        }
        for address, details in sorted(indicators.items())
        if indicator_query in address.casefold()
        or indicator_query in details["label"].casefold()
    ]
    if indicator_rows:
        st.dataframe(indicator_rows, hide_index=True, width="stretch")
    else:
        st.info("No indicators match that search.")
    st.markdown(
        '<div class="signal-note">To manage this list, edit '
        '<code>data/threat_ips.csv</code> in your project. Use trusted, '
        "current indicators and document their source and expiry.</div>",
        unsafe_allow_html=True,
    )

if current_page == "Activity":
    st.subheader("Investigation history")
    st.caption("Recent checks are stored in the local SQLite event database.")
    if events:
        filter_col, search_col = st.columns([1, 2])
        with filter_col:
            status_filter = st.selectbox(
                "Filter by status",
                ["All statuses", *sorted(status_counts)],
            )
        with search_col:
            history_query = st.text_input(
                "Search IP address",
                placeholder="Type an IP address",
                key="history_query",
            ).strip().casefold()
        filtered_events = [
            event
            for event in events
            if (status_filter == "All statuses" or event["status"] == status_filter)
            and history_query in event["ip_address"].casefold()
        ]
        st.caption(f"Showing {len(filtered_events)} of {len(events)} recent events.")
        st.dataframe(filtered_events, width="stretch", hide_index=True)
        st.download_button(
            "Download filtered history as CSV",
            data=export_events_csv(filtered_events),
            file_name="suspicious_ip_events.csv",
            mime="text/csv",
            type="primary",
        )
    else:
        st.info("No events recorded yet. Checks are added here automatically.")

if current_page == "Settings & deployment":
    st.subheader("Workspace settings")
    st.markdown("#### Connected services")
    st.write(
        f"**Google sign-in:** "
        f"{'Configured and access-controlled' if auth_mode == 'secure' else 'Local development only'}"
    )
    st.write(
        f"**AbuseIPDB:** "
        f"{'API key configured' if api_configured else 'Local indicators only'}"
    )
    st.write(
        f"**Email alerts:** "
        f"{'SMTP configured' if email_is_configured() else 'Not configured'}"
    )
    st.markdown("#### Before deploying publicly")
    st.markdown(
        "- Connect this project's GitHub repository to Streamlit Community Cloud.\n"
        "- Select the repository root `app.py` as the app entry point.\n"
        "- Configure Google OIDC and an explicit `allowed_emails` list in the app's secrets.\n"
        "- Keep the environment set to `production`; never deploy with development access enabled.\n"
        "- Add persistent database storage before relying on hosted event history."
    )
    st.info(
        "The project is available in its GitHub repository. The hosted website "
        "still needs to be created in Streamlit Community Cloud."
    )
    st.markdown("#### Data and privacy")
    st.write(
        "The database stores recent checks on the machine running Streamlit. "
        "Public IPs are sent to AbuseIPDB only when an API key is configured "
        "and a check is run with external lookups enabled."
    )
