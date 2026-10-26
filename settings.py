from __future__ import annotations

import os
from typing import Any

import streamlit as st
from streamlit.errors import StreamlitSecretNotFoundError


def get_setting(name: str, default: str = "") -> str:
    """Read a setting from the environment first, then Streamlit secrets."""
    value = os.getenv(name)
    if value is not None and value.strip():
        return value.strip()
    try:
        secret = st.secrets.get(name, default)
    except StreamlitSecretNotFoundError:
        return default
    if secret == default and name == "APP_ENV":
        try:
            app_settings = st.secrets.get("app", {})
        except StreamlitSecretNotFoundError:
            return default
        if isinstance(app_settings, dict):
            secret = app_settings.get("environment", default)
    return str(secret).strip() if secret is not None else default


def get_section(name: str) -> dict[str, Any]:
    """Return a Streamlit secrets section, or an empty section if unconfigured."""
    try:
        section = st.secrets.get(name, {})
    except StreamlitSecretNotFoundError:
        return {}
    return dict(section) if isinstance(section, dict) else {}
