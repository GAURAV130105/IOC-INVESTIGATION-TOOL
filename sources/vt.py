import os
import time
import requests
from cache import cache_get, cache_set
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY  = os.getenv("VT_API_KEY")
BASE_URL_VT = "https://www.virustotal.com/api/v3"
headers_VT  = {"x-apikey": VT_API_KEY}

TYPE_PATH = {
    "ip":     "ip_addresses",
    "hash":   "files",
    "domain": "domains",
}

# VirusTotal

def vt_request_rescan(indicator, ind_type):
    path = TYPE_PATH.get(ind_type, "domains")
    url  = f"{BASE_URL_VT}/{path}/{indicator}/analyse"

    try:
        response = requests.post(url, headers=headers_VT, timeout=30)
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        print("  [VT] Rescan request failed, using cached report")
        return None

    if response.status_code != 200:
        print(f"  [VT] Rescan request error {response.status_code}, using cached report")
        return None

    return response.json().get("data", {}).get("id")


def vt_wait_for_analysis(analysis_id, timeout=60, poll_interval=15):
    url     = f"{BASE_URL_VT}/analyses/{analysis_id}"
    elapsed = 0

    while elapsed < timeout:
        try:
            response = requests.get(url, headers=headers_VT, timeout=30)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            return False

        if response.status_code != 200:
            return False

        status = response.json().get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return True

        time.sleep(poll_interval)
        elapsed += poll_interval

    print("  [VT] Rescan still queued after timeout, using latest available report")
    return False


def vt_check(indicator, ind_type):

    cached = cache_get(indicator, "virustotal")
    if cached:
        return cached

    analysis_id = vt_request_rescan(indicator, ind_type)
    if analysis_id:
        vt_wait_for_analysis(analysis_id)

    if ind_type == "ip":
        url = f"{BASE_URL_VT}/ip_addresses/{indicator}"
    elif ind_type == "hash":
        url = f"{BASE_URL_VT}/files/{indicator}"
    else:
        url = f"{BASE_URL_VT}/domains/{indicator}"

    try:
        response = requests.get(url, headers=headers_VT, timeout=30)
    except requests.exceptions.Timeout:
        print("  [VT] Request timed out, try again later")
        return None
    except requests.exceptions.ConnectionError:
        print("  [VT] Connection error, check your network")
        return None

    if response.status_code == 404:
        return None
    if response.status_code == 429:
        print("  [VT] Rate limit hit, wait a minute and try again")
        return None
    if response.status_code != 200:
        print(f"  [VT] Error {response.status_code}")
        return None

    attrs = response.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    all_vendor_results = attrs.get("last_analysis_results", {})
    last_dns_records= attrs.get("last_dns_records",{})

    dns_records= []

    for record in last_dns_records:
        record_type = record.get("type", "")
        record_value = record.get("value", "")
        record_ttl = record.get("ttl", "")
        dns_records.append(f"{record_type}: {record_value} (TTL: {record_ttl})")

    malicious_vendors = []

    for vendor_name, vendor_data in all_vendor_results.items():
        if vendor_data.get("category") == "malicious":
            threat_name = vendor_data.get("result", "")
            one_vendor = {
                "vendor": vendor_name,
                "name":   threat_name
            }
            malicious_vendors.append(one_vendor)

    malicious_vendors = malicious_vendors[:5]
    tags = attrs.get("tags", [])
    last_scan_date = attrs.get("last_analysis_date", None)

    result = {
        "malicious":         stats.get("malicious", 0),
        "suspicious":        stats.get("suspicious", 0),
        "harmless":          stats.get("harmless", 0),
        "undetected":        stats.get("undetected", 0),
        "malicious_vendors": malicious_vendors,
        "tags":              tags,
        "last_scan_date":    last_scan_date,
        "dns_records":       dns_records,
    }

    if ind_type == "ip":
        result["country"] = attrs.get("country", "Unknown")
        result["asn"]     = attrs.get("asn", "Unknown")

    cache_set(indicator, "virustotal", result)

    return result
