import datetime

from detect import detect_type
from vt import vt_check
from otx import otx_check
from scoring import combined_verdict
from output import save_results

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
