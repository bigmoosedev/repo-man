import requests
import sys

def check_subdomain_http(domain, subdomain):
    url = f"http://{subdomain}.{domain}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            print(f"[+] Found (HTTP): {url}")
    except requests.exceptions.RequestException as e:
        pass

def check_subdomain_https(domain, subdomain):
    url = f"https://{subdomain}.{domain}"
    try:
        response = requests.get(url, timeout=5, verify=False)
        if response.status_code == 200:
            print(f"[+] Found (HTTPS): {url}")
    except requests.exceptions.RequestException as e:
        pass

def main():
    if len(sys.argv) != 3:
        print("Usage: python subdomain_enum.py <domain> <wordlist>")
        sys.exit(1)

    domain = sys.argv[1]
    wordlist_path = sys.argv[2]

    try:
        with open(wordlist_path, "r") as wordlist_file:
            for line in wordlist_file:
                subdomain = line.strip()
                check_subdomain_https(domain, subdomain)
                check_subdomain_http(domain, subdomain)
    except FileNotFoundError:
        print(f"[-] Wordlist file '{wordlist_path}' not found.")
        sys.exit(1)

if __name__ == "__main__":
    main()

# python subdomain_enum.py example.com wordlist.txt