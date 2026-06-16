import requests
import ipaddress
import os
import datetime
import json
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY  = os.getenv("VT_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

BASE_URL_VT  = "https://www.virustotal.com/api/v3"
BASE_URL_OTX = "https://otx.alienvault.com/api/v1"
headers_VT   = {"x-apikey": VT_API_KEY}
headers_OTX  = {"X-OTX-API-KEY": OTX_API_KEY}

def save_results(indicator, vt_result, otx_result, verdict):
    entry = {
    "timestamp":   datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "indicator":   indicator,
    "vt_result":   vt_result,
    "otx_result":  otx_result,
    "verdict":     verdict
    }
    if os.path.exists("results.json"):
        with open("results.json", "r") as f:
            try:
                result_data = json.load(f)
            except json.JSONDecodeError:
                result_data = []
    else:
        result_data = []
    result_data.append(entry)
    with open("results.json", "w") as f:
        json.dump(result_data, f, indent=4)

    print(f"  Result saved to results.json ({len(result_data)} total)")

def is_valid_ipv4(value):
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False

def is_hash(value):
    return len(value) in [32, 40, 64] and all(c in "0123456789abcdef" for c in value.lower())

def detect_type(indicator):
    if is_valid_ipv4(indicator):
        return "ip"
    if is_hash(indicator):
        return "hash"
    if "." in indicator:
        return "domain"
    return None


# VirusTotal

def vt_check(indicator, ind_type):

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
        return {"status": "Not found"}
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

    return result


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


# Combined verdict

def combined_verdict(vt, otx):

    score     = 0
    breakdown = []

    # VirusTotal signals

    if vt:

        # Malicious count
        malicious = vt.get("malicious", 0)

        if malicious >= 10:
            score += 3
            breakdown.append(f"Malicious count {malicious:<5} → +3")
        elif malicious >= 4:
            score += 2
            breakdown.append(f"Malicious count {malicious:<5} → +2")
        elif malicious >= 1:
            score += 1
            breakdown.append(f"Malicious count {malicious:<5} → +1")
        else:
            breakdown.append(f"Malicious count {malicious:<5} → +0")

        # Suspicious count
        suspicious = vt.get("suspicious", 0)

        if suspicious >= 3:
            score += 1
            breakdown.append(f"Suspicious count {suspicious:<4} → +1")
        else:
            breakdown.append(f"Suspicious count {suspicious:<4} → +0")

        # Vendor reliability
        trusted_vendors = [
            "Kaspersky", "CrowdStrike", "Sophos", "BitDefender",
            "ESET", "Palo Alto Networks", "Microsoft", "Symantec"
        ]

        trusted_hits   = 0
        untrusted_hits = 0

        for v in vt.get("malicious_vendors", []):
            if v["vendor"] in trusted_vendors:
                trusted_hits += 1
            else:
                untrusted_hits += 1

        trusted_points   = min(trusted_hits * 2, 4)
        untrusted_points = min(untrusted_hits * 1, 2)

        score += trusted_points
        score += untrusted_points

        if trusted_hits > 0:
            breakdown.append(f"Trusted vendors  {trusted_hits:<5} → +{trusted_points}  (capped at 4)")
        if untrusted_hits > 0:
            breakdown.append(f"Untrusted vendors {untrusted_hits:<4} → +{untrusted_points}  (capped at 2)")

        # Bad tags
        bad_tags = [
            "tor", "self-signed", "malware", "c2", "ransomware",
            "botnet", "phishing", "scanner", "brute-force", "proxy"
        ]

        tag_points  = 0
        found_tags  = []

        for tag in vt.get("tags", []):
            if tag in bad_tags:
                tag_points += 1
                found_tags.append(tag)

        tag_score = min(tag_points, 3)
        score += tag_score

        if len(found_tags) > 0:
            breakdown.append(f"Bad tags {', '.join(found_tags):<15} → +{tag_score}  (capped at 3)")
        else:
            breakdown.append(f"Bad tags none          → +0")

        # Recency
        if vt.get("last_scan_date"):

            now       = datetime.datetime.now()
            scan_date = datetime.datetime.fromtimestamp(vt["last_scan_date"])
            days_ago  = (now - scan_date).days

            if days_ago <= 7:
                score += 2
                breakdown.append(f"Last scanned {days_ago} days ago      → +2  (very recent)")
            elif days_ago <= 30:
                score += 1
                breakdown.append(f"Last scanned {days_ago} days ago      → +1  (recent)")
            elif days_ago > 180:
                score -= 1
                breakdown.append(f"Last scanned {days_ago} days ago      → -1  (old)")
            else:
                breakdown.append(f"Last scanned {days_ago} days ago      → +0")

    # OTX signals

    if otx:

        # Pulse count
        pulse_count = otx.get("pulse_count", 0)

        if pulse_count >= 10:
            score += 2
            breakdown.append(f"OTX pulses {pulse_count:<8}      → +2  (widely tracked)")
        elif pulse_count >= 1:
            score += 1
            breakdown.append(f"OTX pulses {pulse_count:<8}      → +1")
        else:
            breakdown.append(f"OTX pulses {pulse_count:<8}      → +0")

        # OTX reputation
        reputation = otx.get("reputation", 0)

        if reputation < 0:
            score += 1
            breakdown.append(f"OTX reputation {reputation:<5}    → +1  (negative)")
        else:
            breakdown.append(f"OTX reputation {reputation:<5}    → +0")

        # Pulse recency
        pulse_details      = otx.get("pulse_details", [])
        recent_pulse_found = False

        for p in pulse_details:
            pulse_name = p.get("name", "")
            if "2026" in pulse_name or "2025" in pulse_name:
                recent_pulse_found = True

        if recent_pulse_found:
            score += 1
            breakdown.append(f"Recent pulse (2025/2026)        → +1")
        else:
            breakdown.append(f"Recent pulse (2025/2026)        → +0")

        # Passive DNS recency
        pdns = otx.get("passive_dns", [])
        latest_pdns = None
        for r in pdns:
            last_str = r.get("last", "")
            if not last_str:
                continue
            try:
                last_dt = datetime.datetime.fromisoformat(last_str.replace("Z", ""))
                if latest_pdns is None or last_dt > latest_pdns:
                    latest_pdns = last_dt
            except ValueError:
                pass

        if latest_pdns:
            days_since = (datetime.datetime.now() - latest_pdns).days
            if days_since <= 30:
                score += 1
                breakdown.append(f"Passive DNS last seen {days_since} days ago  → +1  (active infrastructure)")
            else:
                breakdown.append(f"Passive DNS last seen {days_since} days ago  → +0")
        else:
            breakdown.append(f"Passive DNS last seen unknown   → +0")

    # Final verdict

    if score == 0:
        label = "✅ Clean"
    elif score <= 2:
        label = "⚠️  Suspicious"
    elif score <= 4:
        label = "🟡 Low risk"
    elif score <= 7:
        label = "🟠 Medium risk"
    else:
        label = "🔴 High risk"

    return {
        "verdict":   label,
        "score":     score,
        "breakdown": breakdown
    }


# Unified check

def check_indicator(indicator):

    ind_type = detect_type(indicator)

    if ind_type is None:
        print("Invalid indicator. Enter a valid IPv4, domain, or hash.")
        return

    print(f"\n{'='*45}")
    print(f"  Threat Report: {indicator}")
    print(f"{'='*45}")

    vt  = vt_check(indicator, ind_type)
    otx = otx_check(indicator, ind_type)

    # Print VT results
    if vt:
        print(f"\n  [VirusTotal]")
        print(f"  Malicious  : {vt['malicious']}")
        print(f"  Suspicious : {vt['suspicious']}")
        print(f"  Harmless   : {vt['harmless']}")
        print(f"  Undetected : {vt['undetected']}")

        if ind_type == "ip":
            print(f"  Country    : {vt['country']}")
            print(f"  ASN        : {vt['asn']}")

        if len(vt["tags"]) > 0:
            print(f"  Tags       : {', '.join(vt['tags'][:5])}")

        if vt["last_scan_date"]:
            scan_date = datetime.datetime.fromtimestamp(vt["last_scan_date"])
            print(f"  Last Scan  : {scan_date.strftime('%Y-%m-%d %H:%M')}")

        if vt["dns_records"]:
            print(f"\n  Last DNS Records:")
            for rec in vt["dns_records"]:
                print(f"    {rec}")

        if len(vt["malicious_vendors"]) > 0:
            print(f"\n  Top Malicious Detections:")
            for v in vt["malicious_vendors"]:
                print(f"    {v['vendor']:<20} {v['name']}")

    # Print OTX results
    if otx:
        print(f"\n  [AlienVault OTX]")

        if ind_type == "ip":
            print(f"  Country    : {otx['country']}")
            print(f"  ASN        : {otx['asn']}")
            print(f"  Reputation : {otx['reputation']}")

        print(f"  Pulses     : {otx['pulse_count']} threat reports")

        pulse_details = otx.get("pulse_details", [])

        for i, p in enumerate(pulse_details, 1):
            print(f"\n  Pulse #{i}: {p['name']}")

            if p["adversary"] != "":
                print(f"    Threat Actor  : {p['adversary']}")

            if len(p["families"]) > 0:
                print(f"    Malware Family: {', '.join(p['families'])}")

            if len(p["tags"]) > 0:
                print(f"    Tags          : {', '.join(p['tags'][:5])}")

            if p["ref"] != "":
                print(f"    Reference     : {p['ref']}")

        pdns = otx.get("passive_dns", [])
        if pdns:
            print(f"\n  Passive DNS ({len(pdns)} record(s), showing first 10):")
            for r in pdns[:10]:
                first = r["first"][:10] if r["first"] else "?"
                last  = r["last"][:10]  if r["last"]  else "?"
                print(f"    [{r['record_type']:<5}] {r['hostname'] or r['address']:<40}  first: {first}  last: {last}")

    # Print score breakdown and verdict
    verdict_result = combined_verdict(vt, otx)

    print(f"\n  Score Breakdown:")
    for line in verdict_result["breakdown"]:
        print(f"    {line}")
    print(f"  {'─'*40}")
    print(f"\n  Verdict  : {verdict_result['verdict']}  (score: {verdict_result['score']})")
    print(f"{'='*45}\n")

    save_results(indicator, vt, otx, verdict_result["verdict"])


# Main loop

while True:
    indicator = input("Enter IP, domain, or file hash (or 'exit' to quit): ").strip()
    if indicator.lower() == "exit":
        break
    check_indicator(indicator)