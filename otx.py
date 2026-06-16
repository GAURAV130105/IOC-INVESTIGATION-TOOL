import os
import requests
from dotenv import load_dotenv

load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")

BASE_URL_OTX = "https://otx.alienvault.com/api/v1"
headers_OTX  = {"X-OTX-API-KEY": OTX_API_KEY}

# AlienVault OTX

def otx_check(indicator, ind_type):

    if ind_type == "ip":
        url = f"{BASE_URL_OTX}/indicators/IPv4/{indicator}/general"
    elif ind_type == "hash":
        url = f"{BASE_URL_OTX}/indicators/file/{indicator}/general"
    else:
        url = f"{BASE_URL_OTX}/indicators/domain/{indicator}/general"
    try:
        response = requests.get(url, headers=headers_OTX, timeout=30)
    except requests.exceptions.Timeout:
        print("  [OTX] Request timed out, try again later")
        return None
    except requests.exceptions.ConnectionError:
        print("  [OTX] Connection error, check your network")
        return None

    if response.status_code == 404:
        print("  [OTX] No record found")
        return None
    if response.status_code == 429:
        print("  [OTX] Rate limit hit")
        return None
    if response.status_code != 200:
        print(f"  [OTX] Error {response.status_code}")
        return None

    data = response.json()

    passive_dns = []
    if ind_type in ("ip", "domain"):
        otx_type = "IPv4" if ind_type == "ip" else "domain"
        pdns_url = f"{BASE_URL_OTX}/indicators/{otx_type}/{indicator}/passive_dns"
        try:
            pdns_resp = requests.get(pdns_url, headers=headers_OTX, timeout=30)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            pdns_resp = None

        if pdns_resp and pdns_resp.status_code == 200:
            for record in pdns_resp.json().get("passive_dns", []):
                passive_dns.append({
                    "hostname":    record.get("hostname", ""),
                    "address":     record.get("address", ""),
                    "record_type": record.get("record_type", ""),
                    "first":       record.get("first", ""),
                    "last":        record.get("last", ""),
                })

    pulse_info = data.get("pulse_info", {})
    pulses = pulse_info.get("pulses", [])
    pulse_count = pulse_info.get("count", 0)
    pulse_details = []
    first_five = pulses[:5]

    for p in first_five:
        pulse_name = p.get("name", "Unnamed")
        adversary  = p.get("adversary", "")
        tags       = p.get("tags", [])

        malware_families_raw = p.get("malware_families", [])
        families = []
        for f in malware_families_raw:
            family_name = f["display_name"]
            families.append(family_name)

        references = p.get("references", [])
        if len(references) > 0:
            first_ref = references[0]
        else:
            first_ref = ""

        one_pulse = {
            "name":      pulse_name,
            "adversary": adversary,
            "families":  families,
            "tags":      tags,
            "ref":       first_ref
        }
        pulse_details.append(one_pulse)

    result = {
        "pulse_count":   pulse_count,
        "pulse_details": pulse_details,
        "passive_dns":   passive_dns,
    }

    if ind_type == "ip":
        result["country"]    = data.get("country_name", "Unknown")
        result["asn"]        = data.get("asn", "Unknown")
        result["reputation"] = data.get("reputation", 0)

    return result
