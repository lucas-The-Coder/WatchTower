import re
import json
import sys
from datetime import datetime, timedelta
import collections


def parse_auth_log(file_path):

    events = []

    log_pattern = re.compile(
        r"(?P<time>\w+ \d+ \d+:\d+:\d+).*?(?P<status>Failed|Accepted) password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    try:
        with open(file_path, "r", encoding="utf-8") as f:

            for line in f:

                match = log_pattern.search(line)

                if not match:
                    continue

                events.append(match.groupdict())

    except FileNotFoundError:
        return []

    return events


def detect_brute_force(events, threshold, window_minutes):
    alerts = []

    fails_by_ip = collections.defaultdict(list)

    for event in events:
        if event.get("status", "").upper() in ("FAIL", "FAILURE", "FAILED"):
            ip = event.get("ip")
            time_str = event.get("time")
            try:
                dt = datetime.strptime(time_str, "%b %d %H:%M:%S")
                fails_by_ip[ip].append(dt)
            except (ValueError, TypeError):
                continue

    for ip, timestamps in fails_by_ip.items():
        timestamps.sort()

        for i, current_time in enumerate(timestamps):
            window_start = current_time - timedelta(minutes=window_minutes)

            fails_in_window = 0
            for t in timestamps[: i + 1]:
                if t >= window_start:
                    fails_in_window += 1

            if fails_in_window >= threshold:
                severity = "HIGH" if fails_in_window > (threshold * 2) else "MEDIUM"

                alert = {
                    "time": current_time.strftime("%b %d %H:%M:%S"),
                    "ip": ip,
                    "severity": severity,
                    "reason": f"Brute force signature detected: {fails_in_window} failed logins within a {window_minutes} - minute window.",
                }

                alerts.append(alert)

                break

    return alerts


def detect_success_after_brute_force(events):
    alerts = []

    events_by_ip = collections.defaultdict(list)

    for event in events:
        ip = event.get("ip")
        time_str = event.get("time")
        status = event.get("status", "").upper()

        try:
            dt = datetime.strptime(time_str, "%b %d %H:%M:%S")

            events_by_ip[ip].append((dt, time_str, status))
        except (ValueError, TypeError):
            continue

    for ip, history in events_by_ip.items():
        history.sort(key=lambda x: x[0])

        for i, (success_dt, success_time_str, success_status) in enumerate(history):
            if success_status in ("ACCEPTED", "SUCCESS", "SUCCEEDED", "OK"):
                window_start = success_dt - timedelta(minutes=10)

                fail_count = 0
                for prev_dt, _, prev_status in history[:i]:
                    if (
                        prev_status in ("FAIL", "FAILURE", "FAILED")
                        and prev_dt >= window_start
                    ):
                        fail_count += 1

                    if fail_count >= 5:
                        alert = {
                            "time": success_time_str,
                            "ip": ip,
                            "severity": "CRITICAL",
                            "reason": f"Possible successful brute force: {fail_count} failures followed by a successful login within 10 minutes",
                        }

                        alerts.append(alert)

                        break
    return alerts


def save_alerts(alerts):
    try:
        with open("alerts.json", "w") as f:
            for alert in alerts:
                json_line = json.dumps(alert)
                f.write(json_line + "\n")

    except (OSError, IOError) as e:
        print(f"Error writing alerts to file: {e}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <sample_auth2.log>")
        return

    log_file_path = sys.argv[1]

    events = parse_auth_log(log_file_path)

    brute_force_alerts = detect_brute_force(events, threshold=5, window_minutes=10)

    critical_alerts = detect_success_after_brute_force(events)

    all_alerts = brute_force_alerts + critical_alerts

    save_alerts(all_alerts)

    for alert in all_alerts:
        print(alert)


if __name__ == "__main__":
    main()
