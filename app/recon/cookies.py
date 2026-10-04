import requests
import sentry_sdk
from typing import Dict, Any


def analyze_cookies(url: str) -> Dict[str, Any]:
    """
    Analyzes the Set-Cookie headers of a given URL for security flags (Secure, HttpOnly).
    Includes an automatic fallback mechanism: attempts HTTPS first, then HTTP.
    """
    url = url.strip()

    if url.startswith(("http://", "https://")):
        targets = [url]
    else:
        targets = [f"https://{url}", f"http://{url}"]

    last_error = ""

    for target in targets:
        with sentry_sdk.start_span(
            op="http.client", description=f"GET Cookies {target}"
        ) as span:
            try:
                headers_req = {"User-Agent": "SecOpsReconBot/1.0 (MLH Challenge)"}
                response = requests.get(target, headers=headers_req, timeout=5)

                span.set_data("http.status_code", response.status_code)

                insecure_cookies = []

                for cookie in response.cookies:
                    is_secure = cookie.secure
                    is_httponly = cookie.has_nonstandard_attr("HttpOnly")

                    issues = []
                    if not is_secure:
                        issues.append("Missing Secure flag")
                    if not is_httponly:
                        issues.append("Missing HttpOnly flag")

                    if issues:
                        insecure_cookies.append({"name": cookie.name, "issues": issues})

                return {
                    "success": True,
                    "url": response.url,
                    "status_code": response.status_code,
                    "total_cookies": len(response.cookies),
                    "insecure_cookies": insecure_cookies,
                }

            except requests.exceptions.Timeout:
                span.set_status("deadline_exceeded")
                last_error = "Connection timed out (5s limit)."
                continue

            except requests.exceptions.RequestException as e:
                span.set_status("internal_error")
                last_error = f"Connection failed: {str(e)}"
                continue

    return {
        "success": False,
        "error": f"{last_error} Target might be unreachable or blocking requests.",
    }
