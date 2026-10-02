# cybersecurity/phishing_detector.py

def detect_phishing(url):

    suspicious = [
        "@",
        "bit.ly",
        "tinyurl",
        "free-money",
        "gift-card"
    ]

    for item in suspicious:

        if item in url.lower():
            return "Possible Phishing"

    return "Looks Safe"