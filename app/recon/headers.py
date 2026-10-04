import requests
import sentry_sdk
from typing import Dict, List, TypedDict, Optional


# Strict Typing for Pylance
class HeaderScanResult(TypedDict, total=False):
    success: bool
    url: str
    status_code: int
    found: List[str]
    missing: List[str]
    raw_headers: Dict[str, str]
    error: str


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
]


def analyze_headers(url: str) -> HeaderScanResult:
    """
    Analyzes the HTTP security headers of a given URL.
    Objectively classifies headers into 'found' and 'missing'.
    """
    url = url.strip()
    targets = (
        [url]
        if url.startswith(("http://", "https://"))
        else [f"https://{url}", f"http://{url}"]
    )
    last_error = ""

    for target in targets:
        with sentry_sdk.start_span(
            op="http.client", description=f"GET Headers {target}"
        ) as span:
            try:
                headers_req = {"User-Agent": "SecOpsReconBot/1.0 (Enterprise Audit)"}
                response = requests.get(target, headers=headers_req, timeout=5)

                span.set_data("http.status_code", response.status_code)

                found_headers = []
                missing_headers = []

                # Case-insensitive header matching
                response_keys = [k.lower() for k in response.headers.keys()]
                for h in SECURITY_HEADERS:
                    if h.lower() in response_keys:
                        found_headers.append(h)
                    else:
                        missing_headers.append(h)

                return {
                    "success": True,
                    "url": response.url,
                    "status_code": response.status_code,
                    "found": found_headers,
                    "missing": missing_headers,
                    "raw_headers": dict(response.headers),
                }

            except requests.exceptions.Timeout:
                span.set_status("deadline_exceeded")
                last_error = "Connection timed out (5s limit)."
                continue
            except requests.exceptions.RequestException as e:
                span.set_status("internal_error")
                last_error = f"Connection failed: {str(e)}"
                continue

    return {"success": False, "error": f"{last_error} Target unreachable."}
