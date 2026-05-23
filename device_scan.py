import subprocess
import platform
import socket

NETWORK_PREFIX = "129.65.6."

def ping(ip):
    flag = "-n" if platform.system().lower() == "windows" else "-c"

    result = subprocess.run(
        ["ping", flag, "1", "-w", "500", ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0

print("Scanning local network...")

for i in range(0, 145):
    ip = NETWORK_PREFIX + str(i)
    print(f"Checking {ip}...")

    if ping(ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = "Unknown"

        print(f"FOUND: {ip} | {hostname}")

print("Scan complete.")