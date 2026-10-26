from __future__ import annotations

import smtplib
from email.message import EmailMessage

from settings import get_setting


def email_is_configured() -> bool:
    required = (
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_USERNAME",
        "SMTP_PASSWORD",
        "ALERT_FROM",
        "ALERT_TO",
    )
    return all(get_setting(name) for name in required)


def send_alert(result: dict[str, object]) -> None:
    host = get_setting("SMTP_HOST")
    username = get_setting("SMTP_USERNAME")
    password = get_setting("SMTP_PASSWORD")
    sender = get_setting("ALERT_FROM")
    recipient = get_setting("ALERT_TO")
    try:
        port = int(get_setting("SMTP_PORT"))
    except ValueError as error:
        raise ValueError("SMTP_PORT must be a valid port number.") from error
    if not all((host, username, password, sender, recipient)):
        raise ValueError("Email alert settings are incomplete.")
    if not 1 <= port <= 65535:
        raise ValueError("SMTP_PORT must be between 1 and 65535.")

    message = EmailMessage()
    message["Subject"] = f"Suspicious IP detected: {result['ip_address']}"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        "\n".join(
            (
                "The Suspicious IP Checker flagged an address.",
                f"IP address: {result['ip_address']}",
                f"Status: {result['status']}",
                f"Local match: {result['local_match']}",
                f"Abuse confidence score: {result['abuse_score']}",
                f"Details: {result['message']}",
            )
        )
    )

    with smtplib.SMTP(host, port, timeout=10) as server:
        server.starttls()
        server.login(username, password)
        server.send_message(message)
