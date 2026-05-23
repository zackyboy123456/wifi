import csv
import socket
import os
from collections import Counter

INPUT_FILE = "packet_log.csv"
OUTPUT_FILE = "traffic_summary.txt"

# Set this to True only if you really want hostnames.
# False is much faster.
LOOKUP_HOSTNAMES = True

# Only show this many destination IPs.
TOP_DESTINATION_LIMIT = 10


def get_hostname(ip):
    socket.setdefaulttimeout(0.3)

    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def load_and_analyze(filename):
    protocols = Counter()
    destinations = Counter()
    total_packets = 0

    with open(filename, "r", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            total_packets += 1

            protocol = row.get("protocol", "Unknown")
            if not protocol:
                protocol = "Unknown"

            protocols[protocol] += 1

            ip = row.get("destination_ip") or row.get("destination")
            if ip:
                destinations[ip] += 1

    return total_packets, protocols, destinations


def build_report(total_packets, protocols, destinations):
    lines = []

    lines.append("=== Wi-Fi Lab Traffic Summary ===")
    lines.append("")
    lines.append(f"Total packets analyzed: {total_packets}")
    lines.append("")

    lines.append("Protocols:")

    if total_packets == 0:
        lines.append("No packets found.")
    else:
        for protocol, count in protocols.most_common():
            percent = (count / total_packets) * 100
            lines.append(f"{protocol}: {count} packets ({percent:.1f}%)")

    lines.append("")
    lines.append("Top destinations:")

    top_destinations = destinations.most_common(TOP_DESTINATION_LIMIT)

    if not top_destinations:
        lines.append("No destination IPs found.")
    else:
        for ip, count in top_destinations:
            if LOOKUP_HOSTNAMES:
                hostname = get_hostname(ip)
            else:
                hostname = "Hostname lookup skipped"

            lines.append(f"{ip} | {hostname} | packets: {count}")

    lines.append("")
    lines.append("Security Observations:")

    observations_found = False

    if protocols["HTTP"] > 0:
        lines.append("- HTTP traffic detected: some web traffic may be unencrypted.")
        observations_found = True

    if protocols["DNS"] > 0:
        lines.append("- DNS traffic detected: domain lookups may reveal browsing activity.")
        observations_found = True

    if protocols["ARP"] > 20:
        lines.append("- High ARP traffic detected: worth discussing ARP spoofing/MITM risk.")
        observations_found = True

    if protocols["TCP"] > 0:
        lines.append("- TCP traffic detected: active connections were observed.")
        observations_found = True

    if protocols["UDP"] > 0:
        lines.append("- UDP traffic detected: this may include DNS, streaming, or other services.")
        observations_found = True

    for ip, count in top_destinations:
        if count >= 50:
            lines.append(f"- Heavy traffic to {ip}: {count} packets observed.")
            observations_found = True

    if not observations_found:
        lines.append("- No major observations were detected from the current rules.")

    lines.append("- Reminder: these are basic indicators, not proof of an attack.")

    return lines


def save_report(lines, filename):
    with open(filename, "w") as file:
        for line in lines:
            file.write(line + "\n")


def print_report(lines):
    for line in lines:
        print(line)


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found. Run packet_logger.py first.")
        return

    total_packets, protocols, destinations = load_and_analyze(INPUT_FILE)

    report_lines = build_report(total_packets, protocols, destinations)

    print_report(report_lines)
    save_report(report_lines, OUTPUT_FILE)

    print("")
    print(f"Report saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()