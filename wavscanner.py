import requests
import argparse
from bs4 import BeautifulSoup
from colorama import Fore, init
from urllib.parse import urljoin

init(autoreset=True)

# Vulnerability details database
VULNERABILITIES = {
    "SQL Injection": {
        "description": "SQL Injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve.",
        "recommendation": "Use parameterized queries (prepared statements) to prevent user input from being executed as SQL code. Also, validate and sanitize all user input."
    },
    "XSS": {
        "description": "Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.",
        "recommendation": "Encode output to prevent it from being interpreted as active content. Use context-sensitive encoding and frameworks that automatically handle XSS protection."
    },
    "LFI": {
        "description": "Local File Inclusion (LFI) is a vulnerability where an attacker is able to include a file, usually exploiting a \"dynamic file inclusion\" mechanisms implemented in the target application. The vulnerability occurs due to the use of user-supplied input without proper validation.",
        "recommendation": "Avoid passing user-supplied input to filesystem APIs. If unavoidable, use a whitelist of allowed files and properly sanitize the input."
    },
    "Command Injection": {
        "description": "Command Injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell.",
        "recommendation": "Avoid calling OS commands directly. Use built-in library functions instead of external processes to perform the required action."
    },
    "Directory Traversal": {
        "description": "Directory Traversal (or Path Traversal) is a web security vulnerability that allows an attacker to read arbitrary files on the server that is running an application. This might include application code and data, credentials for back-end systems, and sensitive operating system files.",
        "recommendation": "Validate user input before processing it. Ideally, use a whitelist of allowed file names and locations."
    },
    "Open Redirect": {
        "description": "An open redirect is an application security flaw that occurs when a web application redirects users to a URL that is controlled by an attacker. Attackers can use open redirects to trick users into visiting malicious websites, which can then be used to launch phishing attacks or distribute malware.",
        "recommendation": "Avoid using redirects and forwards. If you must use them, do not allow the URL to be controlled by the user."
    },
    "IDOR": {
        "description": "Insecure Direct Object References (IDOR) are a type of access control vulnerability that arises when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability, attackers can bypass authorization and access resources in the system directly, for example database records or files.",
        "recommendation": "Implement access control checks to verify that the user is authorized to access the requested object."
    }
}

found_vulnerabilities = []

def get_forms(url, client):
    try:
        response = client.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] Error: {e}")
        return []

def submit_form(form, url, value, client):
    action = form.get("action")
    post_url = urljoin(url, action)
    method = form.get("method")

    inputs_list = form.find_all("input")
    post_data = {}
    for input_tag in inputs_list:
        input_name = input_tag.get("name")
        input_type = input_tag.get("type")
        input_value = input_tag.get("value")
        if input_type == "text":
            input_value = value

        if input_name:
            post_data[input_name] = input_value

    if method.lower() == "post":
        return client.post(post_url, data=post_data)
    else:
        return client.get(post_url, params=post_data)

def scan_sql_injection(url, form=None, client=None):
    payload = "' OR '1'='1"
    if form:
        response = submit_form(form, url, payload, client)
    else:
        response = client.get(url + payload)
    
    if response and ("error" in response.text.lower() or "syntax" in response.text.lower()):
        found_vulnerabilities.append({"type": "SQL Injection", "url": url, "form": form.get('action') if form else 'N/A'})

def scan_xss(url, form=None, client=None):
    payload = "<script>alert('XSS')</script>"
    if form:
        response = submit_form(form, url, payload, client)
    else:
        response = client.get(url + payload)
    
    if response and payload in response.text:
        found_vulnerabilities.append({"type": "XSS", "url": url, "form": form.get('action') if form else 'N/A'})

def scan_lfi(url, client):
    payload = "../../../../etc/passwd"
    try:
        full_url = urljoin(url, payload)
        response = client.get(full_url)
        if "root:x:0:0" in response.text:
            found_vulnerabilities.append({"type": "LFI", "url": full_url})
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] Error: {e}")

def scan_command_injection(url, form=None, client=None):
    payload = "; ls"
    if form:
        response = submit_form(form, url, payload, client)
    else:
        full_url = urljoin(url, payload)
        response = client.get(full_url)
    
    if response and "root:x:0:0" in response.text:
        found_vulnerabilities.append({"type": "Command Injection", "url": url, "form": form.get('action') if form else 'N/A'})

def scan_directory_traversal(url, client):
    traversal_payloads = [
        "../../../../../../windows/win.ini",
        "../../../../../../etc/passwd",
    ]
    for payload in traversal_payloads:
        full_url = urljoin(url, payload)
        try:
            response = client.get(full_url)
            if response.status_code == 200 and ("root:x:0:0" in response.text or "[fonts]" in response.text.lower()):
                found_vulnerabilities.append({"type": "Directory Traversal", "url": full_url})
                return
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Error scanning {full_url}: {e}")

def scan_open_redirect(url, client):
    payload = "?redirect=http://www.evil.com"
    try:
        response = client.get(url + payload, allow_redirects=False)
        if response.status_code in [301, 302, 303, 307, 308] and "http://www.evil.com" in response.headers.get("Location", ""):
            found_vulnerabilities.append({"type": "Open Redirect", "url": url})
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] Error: {e}")

def scan_idor(url, client):
    try:
        response1 = client.get(url + "?id=1")
        response2 = client.get(url + "?id=2")

        if response1.status_code == 200 and response2.status_code == 200 and response1.text != response2.text:
            found_vulnerabilities.append({"type": "IDOR", "url": url})
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] Error scanning for IDOR: {e}")

def scan_forms(url, client):
    forms = get_forms(url, client)
    print(f"[*] Found {len(forms)} forms on {url}")
    for form in forms:
        scan_sql_injection(url, form, client)
        scan_xss(url, form, client)
        scan_command_injection(url, form, client)

def print_vulnerability_report():
    print(f"\n{Fore.CYAN}--- Vulnerability Report ---")
    if not found_vulnerabilities:
        print(f"{Fore.GREEN}No vulnerabilities found.")
        return

    for vuln in found_vulnerabilities:
        vuln_type = vuln['type']
        details = VULNERABILITIES[vuln_type]
        print(f"\n{Fore.RED}[!] {vuln_type} Found")
        print(f"  {Fore.YELLOW}URL: {vuln['url']}")
        if "form" in vuln:
            print(f"  {Fore.YELLOW}Form: {vuln['form']}")
        print(f"  {Fore.WHITE}Description: {details['description']}")
        print(f"  {Fore.GREEN}Recommendation: {details['recommendation']}")

def main():
    parser = argparse.ArgumentParser(description="Web Application Vulnerability Scanner")
    parser.add_argument("url", help="The URL of the web application to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    target_url = args.url
    
    client = requests.Session()

    print(f"{Fore.YELLOW}[*] Scanning {target_url} for vulnerabilities...")
    scan_lfi(target_url, client)
    scan_command_injection(target_url, client=client)
    scan_directory_traversal(target_url, client)
    scan_open_redirect(target_url, client)
    scan_idor(target_url, client)
    scan_forms(target_url, client)
    
    print_vulnerability_report()

if __name__ == "__main__":
    main()
