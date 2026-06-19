import requests
import os
from cache import cache_get, cache_set


CATEGORY_NAMES = {
    1:  "DNS Compromise",
    2:  "DNS Poisoning",
    3:  "Fraud Orders",
    4:  "DDoS Attack",
    5:  "FTP Brute-Force",
    6:  "Ping of Death",
    7:  "Phishing",
    8:  "Fraud VoIP",
    9:  "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}

def abuseipdb_check(indicator, ind_type):
    if ind_type != "ip":
        return None

    cached = cache_get(indicator, "abuseipdb")
    if cached:
        return cached

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return None

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": indicator,
        "maxAgeInDays": 90,
        "verbose": True,
    }

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=10,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
    except Exception:
        return None

    abuse_score    = data.get("abuseConfidenceScore", 0)
    total_reports  = data.get("totalReports", 0)
    distinct_users = data.get("numDistinctUsers", 0)
    isp            = data.get("isp", "")
    is_tor         = data.get("isTor", False)
    last_reported  = data.get("lastReportedAt", None)
    country        = data.get("countryCode", "")

    raw_reports = data.get("reports", [])

    # Count attack types across all reports
    category_counts = {}
    for report in raw_reports:
        for cat_id in report.get("categories", []):
            name = CATEGORY_NAMES.get(cat_id, f"Category {cat_id}")
            category_counts[name] = category_counts.get(name, 0) + 1

    top_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)

    # Extract up to 10 recent reports
    reports = []
    for report in raw_reports[:10]:
        cat_ids   = report.get("categories", [])
        cat_names = [CATEGORY_NAMES.get(c, f"Category {c}") for c in cat_ids]
        reports.append({
            "reported_at": report.get("reportedAt", ""),
            "categories":  cat_names,
            "comment":     report.get("comment", ""),
        })


    result={
        "abuse_score":    abuse_score,
        "total_reports":  total_reports,
        "distinct_users": distinct_users,
        "isp":            isp,
        "is_tor":         is_tor,
        "last_reported":  last_reported,
        "country":        country,
        "top_categories": top_categories,
        "reports":        reports,
    }
    
    cache_set(indicator,"abuseipdb",result)
    return result