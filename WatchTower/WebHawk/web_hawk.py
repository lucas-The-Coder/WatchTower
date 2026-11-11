import requests
import ssl
import socket
import sys
import json
from urllib.parse import urlparse
from datetime import datetime, timezone


def check_headers(url):
    findings = []

    headers_to_check = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
    ]

    try:
        response = requests.get(url, timeout=5)

    except Exception as e:
        error_finding = {
            "check": "Connection/Request",
            "severity": "HIGH",
            "message": f"Request failed {str(e)}",
        }

        findings.append(error_finding)

        return findings

    for header in headers_to_check:
        if header not in response.headers:
            finding = {"check": header, "severity": "MEDIUM", "message": "MISSING"}
            findings.append(finding)
        else:
            finding = {"check": header, "severity": "OK", "message": "OK"}

            findings.append(finding)

    return findings


def check_ssl(url):
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname
    port = 443

    try:
        context = ssl.create_default_context()
        sock = socket.create_connection((host, port), timeout=5)
        ssock = context.wrap_socket(sock, server_hostname=host)
        cert = ssock.getpeercert()
        expiry_str = cert["notAfter"]
        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (
            expiry_date.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)
        ).days
        ssock.close()
        sock.close()

        if days_left < 30:
            finding = {
                "check": "SSL expiry",
                "severity": "HIGH",
                "message": f"Cert expires in {days_left} days",
            }
        else:
            finding = {
                "check": "SSL expiry",
                "severity": "OK",
                "message": f"Cert expires in {days_left} days",
            }

        findings.append(finding)

        return findings

    except Exception as e:
        finding = {
            "check": "SSL",
            "severity": "HIGH",
            "message": f"SSL check failed: {e}",
        }
        findings.append(finding)
        return findings


def check_sqli_reflection(url):
    findings = []

    payload = "?q=' or 1=1 --"
    test_url = f"{url}{payload}"

    try:
        response = requests.get(test_url, timeout=5)
    except requests.RequestException as e:
        finding = {
            "check": "SQL Injection reflection Check",
            "severity": "ERROR",
            "message": f"Request failed: {str(e)}",
        }
        findings.append(finding)
        return findings

    response_text_lower = response.text.lower()
    sql_errors = [
        "sql syntax",
        "mysql",
        "you have an error in your sql syntax",
        "unclosed quotations mark",
    ]

    has_sql_error = any(error in response_text_lower for error in sql_errors)

    if has_sql_error:
        finding = {
            "check": "SQL Injection Reflection Check",
            "severity": "HIGH",
            "message": "Possible SQL error reflection",
        }
    else:
        finding = {
            "check": "SQL Injection Reflection Check",
            "severity": "OK",
            "message": "No SQL error reflection",
        }

    findings.append(finding)

    return findings


def check_open_ports_web(url):
    findings = []

    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        if not host:
            host = urlparse(f"https://{url}").hostname
    except Exception as e:
        return [
            {
                "check": "Port Scan Check",
                "severity": "ERROR",
                "message": f"Failed to parse host from URL: {str(e)}",
            }
        ]

    ports = [80, 443, 8080, 8443]

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)

        result = s.connect_ex((host, port))

        if result == 0:
            finding = {
                "check": f"Port {port} Status",
                "severity": "INFO",
                "message": f"Port {port} OPEN",
            }

        else:
            finding = {
                "check": f"Port {port} Status",
                "severity": "OK",
                "message": f"Port {port} CLOSED",
            }

        s.close()

        findings.append(finding)

    return findings


def main():
    if len(sys.argv) < 2:
        print("Usage: Python script.py <URL>")
        return

    url = sys.argv[1]

    header_findings = check_headers(url)

    ssl_findings = check_ssl(url)

    sqli_findings = check_sqli_reflection(url)

    port_findings = check_open_ports_web(url)

    all_findings = header_findings + ssl_findings + sqli_findings + port_findings

    try:
        with open("web_report.json", "w") as f:
            json.dump(all_findings, f, indent=4)
        print("Report successfully saved to web_report.json\n")
    except Exception as e:
        print(f"Error saving report to file: {str(e)}\n")

    for finding in all_findings:
        check_name = finding.get("check", "Unknown Check")
        severity = finding.get("severity", "UNKNOWN")
        message = finding.get("message", "No message provided")
        print(f"[{severity}] {check_name}: {message}")


if __name__ == "__main__":
    main()
