import hashlib
import requests
import sys
import json
import re


def check_password_strength(password):
    findings = []
    score = 0

    password_length = len(password)

    if password_length >= 12:
        score += 2
    elif password_length >= 8:
        score += 1

    upper_matches = re.findall(r"[A-Z]", password)
    lower_matches = re.findall(r"[a-z]", password)
    digit_matches = re.findall(r"\d", password)
    char_matches = re.findall(r"[^A-Za-z0-9]", password)

    if upper_matches:
        score += 1

    if lower_matches:
        score += 1

    if digit_matches:
        score += 1

    if char_matches:
        score += 1

    if score >= 6:
        finding = {
            "check": "Password strength",
            "severity": "OK",
            "message": "Strong password",
        }
    elif score >= 3 and score <= 5:
        finding = {
            "check": "Password strength",
            "severity": "MEDIUM",
            "message": "Medium password",
        }
    elif score <= 3:
        finding = {
            "check": "Password strength",
            "severity": "HIGH",
            "message": "Weak password",
        }

    findings.append(finding)

    return findings


def hash_password(password):
    password_bytes = password.encode("utf-8")

    hash_object = hashlib.sha256(password_bytes)

    hashed = hash_object.hexdigest()

    return hashed


def check_pwned(password):
    findings = []

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        error_finding = {
            "check": "Pwned Password Check",
            "severity": "ERROR",
            "message": f"API request failed: {str(e)}",
        }

        findings.append(error_finding)
        return findings

    is_pwned = False
    pwned_count = 0

    for line in response.text.splitlines():
        if ":" in line:
            response_suffix, count_str = line.split(":", 1)

            if response_suffix.upper() == suffix:
                is_pwned = True
                pwned_count = int(count_str)
                break

    if is_pwned:
        finding = {
            "check": "Pwned Password Checked",
            "severity": "HIGH",
            "message": f"Pwned {pwned_count:,} times",
        }
    else:
        finding = {
            "check": "Pwned Password Checked",
            "severity": "OK",
            "message": "Not found in breach",
        }

    findings.append(finding)
    return findings


def crack_hash(target_hash, wordlist_path):
    findings = []

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = f.readlines()
    except FileNotFoundError:
        error_finding = {
            "check": "Hash Cracking Check",
            "severity": "ERROR",
            "message": f"Wordlist file not found: {wordlist_path}",
        }

        findings.append(error_finding)
        return findings

    for word in words:
        clean_word = word.strip()

        word_hash = hashlib.sha256(clean_word.encode("utf-8")).hexdigest()

        if word_hash == target_hash:
            finding = {
                "check": "Hash Cracking Check",
                "severity": "HIGH",
                "message": f"Cracked password is {clean_word}",
            }

            findings.append(finding)
            return findings

    finding = {
        "check": "Hash Cracking Check",
        "severity": "OK",
        "message": "Not cracked with wordlist",
    }

    findings.append(finding)
    return findings


def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <password>")
        sys.exit(1)

    password = sys.argv[1]

    strength_findings = check_password_strength(password)

    hashed_password = hash_password(password)
    print(f"Hashed Password (SHA-256): {hashed_password}")

    pwned_findings = check_pwned(password)

    wordlist_file = "common_passwords.txt"
    crack_findings = crack_hash(hashed_password, wordlist_file)

    combined_findings = strength_findings + pwned_findings + crack_findings

    try:
        with open("hash_report.json", "w") as f:
            json.dump(combined_findings, f, indent=4)
        print("Report successfully saved to hash_report.json")
    except IOError as e:
        print(f"Error saving report to file: {e}")

    print("\n--- Password Security Findings ---")
    for finding in combined_findings:
        print(
            f"[{finding['check']}] Severity: {finding['severity']} - {finding['message']}"
        )


if __name__ == "__main__":
    main()
