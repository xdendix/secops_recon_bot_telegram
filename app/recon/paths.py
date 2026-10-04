import requests
import sentry_sdk
import concurrent.futures
from typing import List, TypedDict


# Strict Typing for Pylance
class PathScanResult(TypedDict, total=False):
    success: bool
    url: str
    found_paths: List[str]
    error: str


SENSITIVE_PATHS = [
    "robots.txt",
    ".env",
    ".git/HEAD",
    "sitemap.xml",
    "admin/",
    "backup.zip",
    "api/v1/health",
]


def analyze_paths(url: str) -> PathScanResult:
    """
    Performs a concurrent directory brute-force attack (Dir-Buster lite)
    to discover exposed sensitive files and administrative endpoints.
    """
    url = url.strip().rstrip("/")
    target_base = url if url.startswith(("http://", "https://")) else f"https://{url}"

    found_paths = []

    with sentry_sdk.start_span(
        op="http.client.dirbuster", description=f"Path Scan {target_base}"
    ) as span:

        def check_path(path: str) -> str:
            target_url = f"{target_base}/{path}"
            try:
                headers_req = {"User-Agent": "SecOpsReconBot/1.0 (Enterprise Audit)"}
                # allow_redirects=False mencegah bot mengikuti redirect ke homepage
                response = requests.get(
                    target_url, headers=headers_req, timeout=3, allow_redirects=False
                )

                # Hanya catat temuan yang terbukti valid secara sekuritas
                if response.status_code == 200:
                    return f"/{path} (200 OK)"
                elif response.status_code in [401, 403]:
                    return f"/{path} ({response.status_code} Forbidden/Unauthorized)"
                # Status 301/302 secara sengaja diabaikan untuk mencegah false positive dari catch-all routing

            except requests.exceptions.RequestException:
                pass
            return ""

        try:
            # Concurrent scanning for maximum performance (Enterprise standard)
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                results = executor.map(check_path, SENSITIVE_PATHS)
                for res in results:
                    if res:
                        found_paths.append(res)
        except Exception as e:
            span.set_status("internal_error")
            return {
                "success": False,
                "url": target_base,
                "found_paths": [],
                "error": str(e),
            }

        span.set_data("paths_found", len(found_paths))

        return {
            "success": True,
            "url": target_base,
            "found_paths": found_paths,
            "error": "",
        }
