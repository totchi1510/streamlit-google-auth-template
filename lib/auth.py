from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
import time
import math

import streamlit as st
from streamlit.errors import StreamlitSecretNotFoundError

UNIVERSITY_DOMAINS = ("s.okayama-u.ac.jp", "okayama-u.ac.jp")


@dataclass(frozen=True)
class UniversityUser:
    id: str
    email: str
    hosted_domain: str


def university_user(
    claims: Mapping,
    email_domains: Sequence[str] = UNIVERSITY_DOMAINS,
    hosted_domains: Sequence[str] = UNIVERSITY_DOMAINS,
) -> UniversityUser | None:
    """Accept only claims already verified by Streamlit's Google OIDC provider."""
    sub = claims.get("sub")
    email = claims.get("email")
    hd = claims.get("hd")
    if (
        not isinstance(sub, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", sub)
        or not isinstance(email, str)
        or claims.get("email_verified") is not True
        or not isinstance(hd, str)
    ):
        return None
    email = email.strip().lower()
    hd = hd.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+", email):
        return None
    if email.split("@")[1] not in email_domains or hd not in hosted_domains:
        return None
    # Streamlit's identity cookie can outlive the Google ID token.
    expires_at = claims.get("exp")
    if not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool):
        return None
    if not math.isfinite(expires_at) or expires_at <= time.time():
        return None
    return UniversityUser(id=f"google:{sub}", email=email, hosted_domain=hd)


def _secret_section(name: str) -> Mapping:
    try:
        return st.secrets.get(name, {})
    except (StreamlitSecretNotFoundError, FileNotFoundError):
        return {}


def google_auth_configured() -> bool:
    config = _secret_section("auth")
    required = ("client_id", "client_secret", "cookie_secret", "redirect_uri", "server_metadata_url")
    return all(
        isinstance(config.get(key), str)
        and bool(config[key].strip())
        and not config[key].startswith("replace-")
        for key in required
    ) and config.get("server_metadata_url") == "https://accounts.google.com/.well-known/openid-configuration"


def get_current_user() -> UniversityUser:
    if getattr(st.user, "is_logged_in", False) is not True:
        raise PermissionError("unauthorized")
    policy = _secret_section("access")
    user = university_user(
        st.user.to_dict(),
        policy.get("allowed_email_domains", UNIVERSITY_DOMAINS),
        policy.get("allowed_google_hosted_domains", UNIVERSITY_DOMAINS),
    )
    if user is None:
        raise PermissionError("forbidden")
    return user


def require_user() -> UniversityUser:
    if getattr(st.user, "is_logged_in", False) is not True:
        configured = google_auth_configured()
        if st.button("Googleでログイン", icon=":material/login:", disabled=not configured):
            st.login()
        if not configured:
            st.info("現在ログインを利用できません。")
        st.stop()
    try:
        return get_current_user()
    except PermissionError:
        st.error("このアカウントは利用対象外か、ログインの有効期限が切れています。")
        if st.button("ログアウト", icon=":material/logout:"):
            st.logout()
        st.stop()
