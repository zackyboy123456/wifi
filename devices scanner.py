import ipaddress
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed


Fun_ports = {
    # Very high priority
    21: {
        "name": "FTP - often unencrypted",
        "points": 4,
        "stride": ["Information Disclosure"],
        "fix": "Turn off FTP if you do not use it."
    },
    23: {
        "name": "Telnet - high risk, disable if possible",
        "points": 5,
        "stride": ["Information Disclosure", "Tampering", "Elevation of Privilege"],
        "fix": "Turn off Telnet if you can."
    },
    80: {
        "name": "HTTP admin page - check for default password",
        "points": 3,
        "stride": ["Spoofing", "Information Disclosure", "Elevation of Privilege"],
        "fix": "Check the admin page and change the default password."
    },
    445: {
        "name": "SMB file sharing",
        "points": 4,
        "stride": ["Information Disclosure", "Tampering"],
        "fix": "Turn off file sharing if you do not need it."
    },
    554: {
        "name": "RTSP camera stream",
        "points": 4,
        "stride": ["Information Disclosure"],
        "fix": "Make sure camera streams are password protected."
    },
    3389: {
        "name": "RDP remote desktop - risky if exposed",
        "points": 5,
        "stride": ["Spoofing", "Elevation of Privilege"],
        "fix": "Turn off remote desktop if you do not use it."
    },
    5900: {
        "name": "VNC remote desktop - risky if exposed",
        "points": 5,
        "stride": ["Spoofing", "Information Disclosure", "Elevation of Privilege"],
        "fix": "Turn off VNC if you do not use it."
    },

    # Admin/web interfaces
    22: {
        "name": "SSH - secure only with strong passwords",
        "points": 2,
        "stride": ["Spoofing", "Elevation of Privilege"],
        "fix": "Use a strong password or turn off SSH if you do not need it."
    },
    443: {
        "name": "HTTPS admin page",
        "points": 2,
        "stride": ["Spoofing", "Elevation of Privilege"],
        "fix": "Make sure the admin password is not default."
    },
    81: {
        "name": "Alternate HTTP admin page",
        "points": 3,
        "stride": ["Information Disclosure", "Elevation of Privilege"],
        "fix": "Check what this page is and secure it."
    },
    88: {
        "name": "Alternate web/camera admin page",
        "points": 3,
        "stride": ["Information Disclosure", "Elevation of Privilege"],
        "fix": "Check if this is a camera or admin page."
    },
    631: {
        "name": "IPP printer service",
        "points": 2,
        "stride": ["Information Disclosure", "Tampering"],
        "fix": "Update printer firmware and check printer settings."
    },
    8000: {
        "name": "Alternate HTTP / camera/NVR service",
        "points": 3,
        "stride": ["Information Disclosure", "Elevation of Privilege"],
        "fix": "Check if this is a camera, DVR, or admin page."
    },
    8008: {
        "name": "Common IoT HTTP service",
        "points": 2,
        "stride": ["Information Disclosure"],
        "fix": "Make sure you know what device this is."
    },
    8080: {
        "name": "Alternate HTTP admin page",
        "points": 3,
        "stride": ["Information Disclosure", "Elevation of Privilege"],
        "fix": "Check the page and change default login info."
    },
    8081: {
        "name": "Alternate HTTP admin page",
        "points": 3,
        "stride": ["Information Disclosure", "Elevation of Privilege"],
        "fix": "Check the page and change default login info."
    },
    8443: {
        "name": "Alternate HTTPS admin page",
        "points": 2,
        "stride": ["Spoofing", "Elevation of Privilege"],
        "fix": "Make sure the password is strong."
    },
    8888: {
        "name": "Common IoT/web service",
        "points": 3,
        "stride": ["Information Disclosure", "Elevation of Privilege"],
        "fix": "Figure out what service this is."
    },
    9000: {
        "name": "Web/admin or app service",
        "points": 3,
        "stride": ["Information Disclosure", "Elevation of Privilege"],
        "fix": "Check what is running here."
    },
    9443: {
        "name": "Alternate HTTPS admin page",
        "points": 2,
        "stride": ["Spoofing", "Elevation of Privilege"],
        "fix": "Make sure the password is strong."
    },

    # File sharing / NAS
    139: {
        "name": "NetBIOS file sharing",
        "points": 4,
        "stride": ["Information Disclosure", "Tampering"],
        "fix": "Turn off old file sharing if not needed."
    },
    2049: {
        "name": "NFS file sharing",
        "points": 4,
        "stride": ["Information Disclosure", "Tampering"],
        "fix": "Turn off NFS if you do not use it."
    },
    548: {
        "name": "Apple Filing Protocol",
        "points": 3,
        "stride": ["Information Disclosure", "Tampering"],
        "fix": "Turn this off if you do not use Apple file sharing."
    },
    5000: {
        "name": "NAS/web admin service",
        "points": 3,
        "stride": ["Information Disclosure", "Elevation of Privilege"],
        "fix": "Check NAS settings and update it."
    },
    5001: {
        "name": "NAS/web admin HTTPS service",
        "points": 3,
        "stride": ["Information Disclosure", "Elevation of Privilege"],
        "fix": "Check NAS settings and update it."
    },

    # Cameras / DVR / NVR
    8554: {
        "name": "Alternate RTSP camera stream",
        "points": 4,
        "stride": ["Information Disclosure"],
        "fix": "Make sure this camera stream is not open without a password."
    },
    37777: {
        "name": "DVR/NVR camera service",
        "points": 5,
        "stride": ["Information Disclosure", "Elevation of Privilege"],
        "fix": "Check DVR/NVR settings and change default passwords."
    },
    34567: {
        "name": "DVR/NVR camera service",
        "points": 5,
        "stride": ["Information Disclosure", "Elevation of Privilege"],
        "fix": "Check DVR/NVR settings and change default passwords."
    },

    # Discovery/network services
    53: {
        "name": "DNS service",
        "points": 2,
        "stride": ["Spoofing", "Denial of Service"],
        "fix": "Make sure this is supposed to be running DNS."
    },
    123: {
        "name": "NTP time service",
        "points": 1,
        "stride": ["Denial of Service"],
        "fix": "Usually not a big deal, but still good to know about."
    },
    1900: {
        "name": "SSDP/UPnP discovery",
        "points": 3,
        "stride": ["Information Disclosure", "Denial of Service"],
        "fix": "Turn off UPnP if you do not need it."
    },

    # Databases/dev services
    3306: {
        "name": "MySQL database",
        "points": 5,
        "stride": ["Information Disclosure", "Tampering", "Elevation of Privilege"],
        "fix": "A database probably should not be open on a normal home device."
    },
    5432: {
        "name": "PostgreSQL database",
        "points": 5,
        "stride": ["Information Disclosure", "Tampering", "Elevation of Privilege"],
        "fix": "A database probably should not be open unless you set it up."
    },
    6379: {
        "name": "Redis database/cache",
        "points": 5,
        "stride": ["Information Disclosure", "Tampering", "Elevation of Privilege"],
        "fix": "Redis should not be open on a normal home network."
    },
    27017: {
        "name": "MongoDB database",
        "points": 5,
        "stride": ["Information Disclosure", "Tampering", "Elevation of Privilege"],
        "fix": "MongoDB should not be open unless you meant to run it."
    },

    # Mail services
    25: {
        "name": "SMTP mail server",
        "points": 3,
        "stride": ["Spoofing", "Information Disclosure"],
        "fix": "Most home devices should not be running mail services."
    },
    110: {
        "name": "POP3 mail",
        "points": 3,
        "stride": ["Information Disclosure"],
        "fix": "Most home devices should not be running this."
    },
    143: {
        "name": "IMAP mail",
        "points": 3,
        "stride": ["Information Disclosure"],
        "fix": "Most home devices should not be running this."
    },
    587: {
        "name": "SMTP submission",
        "points": 2,
        "stride": ["Spoofing"],
        "fix": "Only keep this if you know why it is there."
    },
    993: {
        "name": "IMAPS mail",
        "points": 2,
        "stride": ["Information Disclosure"],
        "fix": "Only keep this if you know why it is there."
    },
    995: {
        "name": "POP3S mail",
        "points": 2,
        "stride": ["Information Disclosure"],
        "fix": "Only keep this if you know why it is there."
    },
}


wifi_types = {
    "WEP": {
        "points": 6,
        "risk": "very high",
        "info": "WEP is really old and should not be used anymore."
    },
    "WPA": {
        "points": 5,
        "risk": "high",
        "info": "WPA is old too. It is better than WEP, but still not great."
    },
    "WPA2": {
        "points": 2,
        "risk": "medium",
        "info": "WPA2 is pretty normal. It is okay if your Wi-Fi password is strong."
    },
    "WPA3": {
        "points": 0,
        "risk": "low",
        "info": "WPA3 is the best common home Wi-Fi option right now."
    },
    "UNKNOWN": {
        "points": 1,
        "risk": "unknown",
        "info": "Could not figure out what Wi-Fi security is being used."
    }
}


def clean_wifi_name(text: str) -> str:
    text = text.upper()

    if "WPA3" in text:
        return "WPA3"
    if "WPA2" in text:
        return "WPA2"
    if "WPA" in text:
        return "WPA"
    if "WEP" in text:
        return "WEP"

    return "UNKNOWN"


def get_wifi_security() -> str:
    # Tries to find the Wi-Fi security on its own.

    system = platform.system().lower()

    try:
        if system == "windows":
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=5
            )

            output = result.stdout

            for line in output.splitlines():
                if "Authentication" in line:
                    return clean_wifi_name(line)

            return clean_wifi_name(output)

    except Exception:
        return "UNKNOWN"


def ping_host(ip: str) -> bool:
    # Return True if host responds to ping

    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "500", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        return result.returncode == 0
    except Exception:
        return False


def get_local_network() -> str:
    try:
        # This does not really connect to google.
        # It just helps the computer find what network it is using.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(network)

    except Exception:
        # Safe fallback for many home routers
        return "192.168.1.0/24"


def check_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    # Return True if TCP port is open.
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def get_risk_word(score: int) -> str:
    if score >= 12:
        return "high"
    elif score >= 5:
        return "medium"
    else:
        return "low"


def think_about_risk(open_ports: list[int]) -> dict:
    # This is the risk / STRIDE part for the project

    score = 0
    stride_stuff = []
    fixes = []

    for port in open_ports:
        score += Fun_ports[port]["points"]

        for thing in Fun_ports[port]["stride"]:
            if thing not in stride_stuff:
                stride_stuff.append(thing)

        if Fun_ports[port]["fix"] not in fixes:
            fixes.append(Fun_ports[port]["fix"])

    return {
        "score": score,
        "word": get_risk_word(score),
        "stride": stride_stuff,
        "fixes": fixes
    }


def scan_host(ip: str) -> dict:
    # Ping a host and scan selected ports if alive.
    result = {
        "ip": ip,
        "alive": False,
        "open_ports": [],
        "risk_score": 0,
        "risk_word": "low",
        "stride": [],
        "fixes": []
    }

    if not ping_host(ip):
        return result

    result["alive"] = True

    for port in Fun_ports:
        if check_port(ip, port):
            result["open_ports"].append(port)

    risk = think_about_risk(result["open_ports"])

    result["risk_score"] = risk["score"]
    result["risk_word"] = risk["word"]
    result["stride"] = risk["stride"]
    result["fixes"] = risk["fixes"]

    return result


def scan_network(network: str):
    # Scan a local network range, such as 192.168.1.0/24.
    net = ipaddress.ip_network(network, strict=False)

    if not net.is_private:
        raise ValueError("Only scan your own private network.")

    hosts = [str(ip) for ip in net.hosts()]

    print(f"Scanning {network}...")
    print("This may take a while.....")

    found_devices = []
    count = 1

    with ThreadPoolExecutor(max_workers=64) as executor:
        futures = [executor.submit(scan_host, host) for host in hosts]

        for future in as_completed(futures):
            result = future.result()

            if count == 1:
                print(f"\rworking.", end="", flush=True)
            if count == 2:
                print(f"\rworking..", end="", flush=True)
            if count == 3:
                print(f"\rworking...", end="", flush=True)
            if count == 4:
                print(f"\rworking....", end="", flush=True)
                count = 1

            count += 1

            if result["alive"]:
                found_devices.append(result)

    print()

    return found_devices


def print_wifi_stuff(wifi_security: str):
    print("\n" + "=" * 50)
    print("wifi security stuff")
    print("=" * 50)

    print(f"what this computer thinks your wifi is using: {wifi_security}")
    print(f"risk for that: {wifi_types[wifi_security]['risk']}")
    print(f"note: {wifi_types[wifi_security]['info']}\n")

    print("comparison:")
    for name in wifi_types:
        if name == "UNKNOWN":
            continue

        extra = ""
        if name == wifi_security:
            extra = "  <-- yours"

        print(f"{name}: {wifi_types[name]['risk']} risk{extra}")
        print(f"  {wifi_types[name]['info']}\n")

    print("quick take:")
    print("  - WEP is bad")
    print("  - WPA is old")
    print("  - WPA2 is usually fine with a strong password")
    print("  - WPA3 is the best option if your router supports it")


def print_results(devices: list[dict]):
    print("\n" + "=" * 50)
    print("Summary")
    print("=" * 50)

    if not devices:
        print("no devices found")
        print("some devices block ping so this does not always mean nothing is there")
        return

    for device in sorted(devices, key=lambda d: d["ip"]):
        ip = device["ip"]
        ports = device["open_ports"]

        if ports:
            print(f"\n{ip} may be intresting:")
            print(f"risk score: {device['risk_score']}")
            print(f"risk level: {device['risk_word']}")

            print("\nopen ports:")
            for port in ports:
                print(f"  - {port}: {Fun_ports[port]['name']}")

            print("\nSTRIDE stuff:")
            if device["stride"]:
                for thing in device["stride"]:
                    print(f"  - {thing}")
            else:
                print("  - nothing major")

            print("\nwhat i would fix:")
            for fix in device["fixes"]:
                print(f"  - {fix}")

        else:
            print(f"\n{ip}: nothing cool")
            print(f"risk score: {device['risk_score']}")
            print(f"risk level: {device['risk_word']}")

        print("-" * 50)


def save_report(devices: list[dict], network_range: str, wifi_security: str):
    file_name = "network_risk_report.txt"

    with open(file_name, "w", encoding="utf-8") as file:
        file.write("Home Network Risk Report\n")
        file.write("=" * 50 + "\n\n")

        file.write(f"network scanned: {network_range}\n")
        file.write(f"wifi security found: {wifi_security}\n")
        file.write(f"wifi risk: {wifi_types[wifi_security]['risk']}\n")
        file.write(f"wifi note: {wifi_types[wifi_security]['info']}\n\n")

        file.write("what this project does:\n")
        file.write("- finds devices on a home network\n")
        file.write("- checks common ports\n")
        file.write("- gives a risk score\n")
        file.write("- uses STRIDE to explain the risk\n")
        file.write("- compares WEP, WPA, WPA2, and WPA3\n")
        file.write("- tries to find the wifi security type by itself\n")
        file.write("- gives basic fixes\n\n")

        file.write("wifi comparison:\n")
        for name in wifi_types:
            if name != "UNKNOWN":
                file.write(f"- {name}: {wifi_types[name]['risk']} risk. {wifi_types[name]['info']}\n")

        file.write("\nscan results:\n")
        file.write("=" * 50 + "\n")

        if not devices:
            file.write("no devices found\n")
            file.write("some devices block ping so this scan can miss things\n")

        for device in sorted(devices, key=lambda d: d["ip"]):
            file.write(f"\ndevice: {device['ip']}\n")
            file.write(f"risk score: {device['risk_score']}\n")
            file.write(f"risk level: {device['risk_word']}\n")

            file.write("\nopen ports:\n")
            if device["open_ports"]:
                for port in device["open_ports"]:
                    file.write(f"- {port}: {Fun_ports[port]['name']}\n")
            else:
                file.write("- nothing cool found\n")

            file.write("\nSTRIDE stuff:\n")
            if device["stride"]:
                for thing in device["stride"]:
                    file.write(f"- {thing}\n")
            else:
                file.write("- nothing major from the ports checked\n")

            file.write("\nwhat i would fix:\n")
            if device["fixes"]:
                for fix in device["fixes"]:
                    file.write(f"- {fix}\n")
            else:
                file.write("- no fixes from the ports checked\n")

            file.write("\n" + "-" * 50 + "\n")

    print(f"\nreport saved as: {file_name}")


if __name__ == "__main__":
    print("home network scanner thing")
    print("=" * 50)

    wifi_security = get_wifi_security()
    print(f"\nwifi security found: {wifi_security}")

    network_range = get_local_network()
    print(f"auto detected network: {network_range}\n")

    devices = scan_network(network_range)

    print_wifi_stuff(wifi_security)
    print_results(devices)
    save_report(devices, network_range, wifi_security)