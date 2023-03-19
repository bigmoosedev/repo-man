import requests
import sys

sensitive_paths = [
    "/.git/config",
    "/.svn/entries",
    "/.env",
    "/.htaccess",
    "/.htpasswd",
    "/config.php",
    "/wp-config.php",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/backup/",
    "/db_backup/",
    "/logs/",
    "/log/",
    "/error_log",
    "/access_log",
    "/admin/",
    "/wp-admin/",
    "/wp-content/plugins/",
    "/wp-content/uploads/",
    "/wp-content/upgrade/",
    "/wp-content/themes/",
    "/wp-includes/",
    "/web.config",
    "/php.ini",
    "/phpmyadmin/",
    "/test/",
    "/debug/",
    "/cgi-bin/",
    "/.well-known/",
    "/includes/",
    "/.DS_Store",
    "/composer.json",
    "/composer.lock",
    "/package.json",
    "/package-lock.json",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/security.txt",
]

def check_sensitive_paths(url):
    for path in sensitive_paths:
        target = f"{url}{path}"
        response = requests.get(target)

        if response.status_code == 200:
            print(f"[+] Potentially sensitive file/directory found at: {target}")
        else:
            print(f"[-] Not found: {target}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python web_sensitive_files.py <url>")
        sys.exit(1)

    url = sys.argv[1].rstrip("/")
    check_sensitive_paths(url)

if __name__ == "__main__":
    main()

# python sneakypeeky.py http://example.com