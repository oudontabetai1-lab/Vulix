"""Browser auto-open policy shared by the CLI and scan engines."""

import os
import webbrowser


def auto_open_disabled() -> bool:
    """Return whether browser auto-opening is disabled for tests or CI."""
    disabled = os.environ.get("WSCAN_NO_AUTO_OPEN", "").strip().lower()
    ci = os.environ.get("CI", "").strip().lower()
    return disabled in {"1", "true", "yes", "on"} or ci in {"1", "true", "yes", "on"}


def open_in_browser(url: str) -> bool:
    """Open a URL unless the current environment disables automatic opening."""
    if auto_open_disabled():
        return False
    return bool(webbrowser.open(url))
