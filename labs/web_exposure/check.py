import argparse
import ipaddress
import tempfile
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

# Common files and directories that are often exposed by mistake.
COMMON_PATHS = (
    "admin/", "login/", "config.php", "index.php.bak", ".git/", "robots.txt", "sitemap.xml",
    "wp-login.php", "wp-admin/", ".htaccess", "config.json", "db_backup/", "backup/", "old/",
    "test/", "temp/", "uploads/", "phpinfo.php",
)

TIMEOUT_SECONDS = 5


def normalize_base_url(base_url):
    """Accept only explicit loopback URLs for a local practice server."""
    parsed = urlsplit(base_url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter an http(s) URL whose host is localhost or a loopback IP.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Credentials, query strings, and fragments are not accepted.")

    host = parsed.hostname.lower()
    is_loopback = host == "localhost"
    if not is_loopback:
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = False
    if not is_loopback:
        raise ValueError("Remote hosts are not supported; use localhost or a loopback IP.")

    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Surface 3xx as HTTPError instead of following it.


# An empty ProxyHandler ignores HTTP(S)_PROXY settings so loopback requests stay local.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def check_url(base_url, endpoint):
    """Send one HEAD request; return the HTTP status code, or None on connection error."""
    url = f"{base_url}/{endpoint.lstrip('/')}"
    request = urllib.request.Request(url, method="HEAD")
    try:
        with _OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (urllib.error.URLError, OSError) as error:
        print(f"[-] Error checking {url}: {getattr(error, 'reason', error)}")
        return None


def scan(base_url, paths=COMMON_PATHS):
    """Check each path and return a list of {"path", "status", "verdict"} findings."""
    findings = []
    for path in paths:
        status = check_url(base_url, path)
        if status is None:
            continue
        if status == 200:
            verdict = "found"
        elif status in (401, 403):
            verdict = "access_controlled"
        elif 300 <= status < 400:
            verdict = "redirect_not_followed"
        else:
            continue
        findings.append({"path": path, "status": status, "verdict": verdict})
    return findings


class _DemoHandler(SimpleHTTPRequestHandler):
    """Static practice server; /admin/ answers 403 to show an access-controlled path."""

    def send_head(self):
        if self.path.startswith("/admin"):
            self.send_error(403)
            return None
        return super().send_head()

    def log_message(self, format, *args):
        pass


def _write_demo_site(root):
    files = {
        "index.html": "<h1>CyberSHIELD practice server</h1>",
        "robots.txt": "User-agent: *\nDisallow: /backup/\n",
        ".git/HEAD": "ref: refs/heads/main\n",
        "backup/site.tar.gz.txt": "Synthetic placeholder, not a real backup.\n",
        "config.json": '{"debug": true, "note": "synthetic demo file"}\n',
        "admin/index.html": "Restricted",
    }
    for relative, content in files.items():
        target = Path(root) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


@contextmanager
def demo_server():
    """Serve a throwaway synthetic site on 127.0.0.1 and yield its base URL."""
    with tempfile.TemporaryDirectory() as root:
        _write_demo_site(root)
        handler = partial(_DemoHandler, directory=root)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}"
        finally:
            server.shutdown()
            server.server_close()


LABELS = {
    "found": "[+] Found",
    "access_controlled": "[+] Access controlled (might exist)",
    "redirect_not_followed": "[!] Redirect not followed",
}


def _report(base_url):
    print(f"\nChecking {base_url} ...\n")
    findings = scan(base_url)
    if not findings:
        print("No configured paths responded with 200, 3xx, 401, or 403.")
    for finding in findings:
        print(f"{LABELS[finding['verdict']]} ({finding['status']}): {base_url}/{finding['path']}")


def main():
    parser = argparse.ArgumentParser(
        description="Check a local practice server for commonly exposed paths (loopback only)."
    )
    parser.add_argument("url", nargs="?", help="e.g. http://127.0.0.1:8000")
    parser.add_argument(
        "--demo", action="store_true",
        help="start a temporary synthetic practice server on 127.0.0.1 and check it",
    )
    args = parser.parse_args()

    if args.demo:
        with demo_server() as base_url:
            _report(base_url)
        return

    raw = args.url or input("Local practice server URL (e.g., http://127.0.0.1:8000): ")
    try:
        base_url = normalize_base_url(raw)
    except ValueError as error:
        raise SystemExit(f"Invalid target: {error}")
    _report(base_url)


if __name__ == "__main__":
    main()
