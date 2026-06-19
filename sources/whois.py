import os
import datetime
import requests
from cache import cache_get, cache_set
from dotenv import load_dotenv

load_dotenv()
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")
BASE_URL_WHOIS = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

def whois_check(indicator, ind_type):

    # domain only guard
    if ind_type != "domain":
        return None

    # cache check first
    cached = cache_get(indicator, "whois")
    if cached:
        return cached

    try:
        response = requests.get(BASE_URL_WHOIS, params={
            "apiKey": WHOIS_API_KEY,
            "domainName": indicator,
            "outputFormat": "JSON"
        }, timeout=10)
    except requests.exceptions.Timeout:
        print("  [WHOIS] Request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("  [WHOIS] Connection error")
        return None

    if response.status_code == 401:
        print("  [WHOIS] Invalid API key")
        return None
    if response.status_code == 429:
        print("  [WHOIS] Rate limit hit")
        return None
    if response.status_code != 200:
        print(f"  [WHOIS] Error {response.status_code}")
        return None

    whois_record = response.json().get("WhoisRecord", {})
    registrant   = whois_record.get("registrant", {})

    # privacy masking check
    org = (registrant.get("organization") or "").lower()
    privacy_keywords = ["privacy", "proxy", "redacted", "whoisguard", "protect", "withheld"]
    privacy_masked = any(kw in org for kw in privacy_keywords)

    # domain age
    creation_str = whois_record.get("createdDate")
    domain_age_days = None
    if creation_str:
        try:
            created = datetime.datetime.fromisoformat(creation_str[:19])
            domain_age_days = (datetime.datetime.now() - created).days
        except (ValueError, TypeError):
            pass

    result = {
        "domain":          whois_record.get("domainName"),
        "registrar":       whois_record.get("registrarName"),
        "creation_date":   whois_record.get("createdDate"),
        "expiration_date": whois_record.get("expiresDate"),
        "updated_date":    whois_record.get("updatedDate"),
        "name_servers":    whois_record.get("nameServers", {}).get("hostNames", []),
        "status":          whois_record.get("status", ""),
        "country":         registrant.get("country"),
        "privacy_masked":  privacy_masked,
        "domain_age_days": domain_age_days,
    }

    cache_set(indicator, "whois", result)
    return result