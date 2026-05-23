import re

def password_strength_score(password):
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    else:
        feedback.append("Use at least 12 characters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Add numbers.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        feedback.append("Add special characters.")

    common_passwords = {
        "password",
        "password123",
        "admin",
        "qwerty",
        "letmein",
        "12345678",
        "wifi1234"
    }

    if password.lower() in common_passwords:
        score -= 3
        feedback.append("Avoid common passwords.")

    return max(score, 0), feedback


def encryption_score(encryption_type):
    encryption_type = encryption_type.upper()

    if encryption_type == "WPA3":
        return 4, "WPA3 is currently the strongest common home Wi-Fi option."
    elif encryption_type == "WPA2":
        return 3, "WPA2 is acceptable if paired with a strong password."
    elif encryption_type == "WPA":
        return 1, "WPA is outdated and should be replaced."
    elif encryption_type == "WEP":
        return 0, "WEP is insecure and should not be used."
    elif encryption_type == "OPEN":
        return 0, "Open networks provide no encryption."
    else:
        return 0, "Unknown encryption type."


def analyze_network(ssid, encryption_type, password, wps_enabled):
    total_score = 0
    recommendations = []

    enc_score, enc_message = encryption_score(encryption_type)
    total_score += enc_score
    recommendations.append(enc_message)

    pw_score, pw_feedback = password_strength_score(password)
    total_score += pw_score
    recommendations.extend(pw_feedback)

    if not wps_enabled:
        total_score += 2
    else:
        recommendations.append("Disable WPS because it can weaken router security.")

    if total_score >= 9:
        rating = "Strong"
    elif total_score >= 6:
        rating = "Moderate"
    else:
        rating = "Weak"

    return {
        "SSID": ssid,
        "Security Rating": rating,
        "Score": f"{total_score}/12",
        "Recommendations": recommendations
    }


def main():
    print("Wi-Fi Security Risk Analyzer")
    print("----------------------------")

    ssid = input("Enter SSID/network name: ")
    encryption_type = input("Encryption type, such as WPA3, WPA2, WPA, WEP, or OPEN: ")
    password = input("Wi-Fi password: ")
    wps_answer = input("Is WPS enabled? yes/no: ").strip().lower()

    wps_enabled = wps_answer == "yes"

    result = analyze_network(ssid, encryption_type, password, wps_enabled)

    print("\nSecurity Report")
    print("---------------")
    print(f"SSID: {result['SSID']}")
    print(f"Security Rating: {result['Security Rating']}")
    print(f"Score: {result['Score']}")

    print("\nRecommendations:")
    for item in result["Recommendations"]:
        print(f"- {item}")


if __name__ == "__main__":
    main()