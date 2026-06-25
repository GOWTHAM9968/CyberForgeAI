# cybersecurity/url_scanner.py

def scan_url(url):

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "bank",
        "update",
        "free",
        "gift"
    ]

    score = 0

    for word in suspicious_words:

        if word in url.lower():
            score += 1

    if score >= 3:
        return "High Risk"

    elif score >= 1:
        return "Medium Risk"

    return "Low Risk"