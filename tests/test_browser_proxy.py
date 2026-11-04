from wscan.browser import _playwright_proxy_options


def test_playwright_proxy_options_split_credentials_and_preserve_safe_cases():
    assert _playwright_proxy_options("http://user:pass@proxy.test:8080") == {
        "server": "http://proxy.test:8080", "username": "user", "password": "pass"
    }
    assert _playwright_proxy_options("http://proxy.test:8080") == {"server": "http://proxy.test:8080"}
    assert _playwright_proxy_options("") is None
