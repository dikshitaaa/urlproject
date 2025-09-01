import re

def check_url(url):
    issues = []

    # Rule 1: HTTPS check
    if not url.startswith("https://"):
        issues.append("Does not use HTTPS")

    # Rule 2: Suspicious keywords
    suspicious_words = ["login", "verify", "update", "banking", "secure", "account"]
    for word in suspicious_words:
        if word in url.lower():
            issues.append(f"Contains suspicious word: {word}")

    # Rule 3: Too many numbers in domain
    domain = re.findall(r"https?://([^/]+)", url)
    if domain:
        domain = domain[0]
        digits = sum(c.isdigit() for c in domain)
        if digits > 3:
            issues.append("Domain has too many numbers")

    # Rule 4: Hyphens in domain
    if "-" in url:
        issues.append("Domain contains hyphens (often used in fake URLs)")

    # Rule 5: Very long URL
    if len(url) > 75:
        issues.append("URL length is unusually long")

    # Final decision
    if issues:
        return " Suspicious URL", issues
    else:
        return "Legitimate URL", issues


if __name__ == "__main__":
    print(" URL Phishing Detector")
    url = input("Enter a URL: ").strip()
    verdict, problems = check_url(url)

    print("\nResult:", verdict)
    if problems:
        print("Reasons:")
        for p in problems:
            print(" -", p)
