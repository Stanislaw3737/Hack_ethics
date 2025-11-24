# Hack_ethics

# WAVScanner - Web Application Vulnerability Scanner

WAVScanner is a Python-based tool designed to scan web applications for common vulnerabilities. It helps identify potential security flaws such as SQL Injection, Cross-Site Scripting (XSS), Local File Inclusion (LFI), Command Injection, Directory Traversal, Open Redirect, and Insecure Direct Object References (IDOR).

## Features

*   **SQL Injection Detection:** Identifies potential SQL injection points in forms and URL parameters.
*   **Cross-Site Scripting (XSS) Detection:** Scans for XSS vulnerabilities in forms and URL parameters.
*   **Local File Inclusion (LFI) Detection:** Checks for LFI vulnerabilities by attempting to access sensitive files like `/etc/passwd`.
*   **Command Injection Detection:** Attempts to detect command injection vulnerabilities.
*   **Directory Traversal Detection:** Scans for directory traversal vulnerabilities by trying to access system files.
*   **Open Redirect Detection:** Identifies open redirect vulnerabilities.
*   **Insecure Direct Object References (IDOR) Detection:** Checks for IDOR vulnerabilities in URL parameters.
*   **Form Scanning:** Automatically discovers and tests forms on the target URL for various vulnerabilities.

## Installation

### Prerequisites

*   Python 3.x

### Steps

1.  Clone the repository (or download `wavscanner.py` and `requirements.txt`):
    ```bash
    git clone <repository-url>
    cd WAVScanner
    ```
    (Note: Assuming the user already has the files in the current directory, I will skip the clone step in the actual instruction.)

2.  Install the required Python packages using `pip`:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To scan a web application, run the `wavscanner.py` script followed by the target URL.

```bash
python wavscanner.py <target_url>
```

**Example:**

```bash
python wavscanner.py http://testphp.vulnweb.com
```

### Arguments

*   `<target_url>`: The URL of the web application to scan (e.g., `http://example.com`).
*   `-v`, `--verbose`: Enable verbose output (currently not implemented in the provided script, but included for completeness if planned for future).

## Vulnerability Report

Upon completion, the scanner will generate a report detailing any discovered vulnerabilities. Each entry in the report includes:

*   **Vulnerability Type:** The specific type of vulnerability found (e.g., SQL Injection, XSS).
*   **URL:** The URL where the vulnerability was detected.
*   **Form (if applicable):** The action URL of the form involved in the vulnerability.
*   **Description:** A brief explanation of the vulnerability.
*   **Recommendation:** Advice on how to mitigate the identified vulnerability.

If no vulnerabilities are found, the report will indicate that.
