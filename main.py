import datetime

from detect import detect_type
from vt import vt_check
from otx import otx_check
from abuseipdb import abuseipdb_check
from scoring import combined_verdict, load_config, resolve_vendor
from output import save_results, print_history, get_history_entry, get_history_count

config = load_config("config.json")


def display_report(indicator, ind_type, vt, otx, abuse):

    print(f"\n{'='*45}")
    print(f"  Threat Report: {indicator}")
    print(f"{'='*45}")

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

            def _vendor_tier(v):
                canonical = resolve_vendor(v["vendor"], config["alias_lookup"])
                if canonical in config["tier1"]:
                    return 1
                elif canonical in config["tier2"]:
                    return 2
                return 3

            for v in sorted(vt["malicious_vendors"], key=_vendor_tier):
                canonical = resolve_vendor(v["vendor"], config["alias_lookup"])
                if canonical in config["tier1"]:
                    tier_label = "(Tier 1)"
                elif canonical in config["tier2"]:
                    tier_label = "(Tier 2)"
                else:
                    tier_label = "(Tier 3)"
                print(f"    {v['vendor']:<20} {v['name']:<30} {tier_label}")

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

    # Print AbuseIPDB results
    if abuse:
        print(f"\n  [AbuseIPDB]")
        print(f"  Abuse Score    : {abuse['abuse_score']}%")
        print(f"  Total Reports  : {abuse['total_reports']}  ({abuse['distinct_users']} distinct users)")
        print(f"  ISP            : {abuse['isp']}")
        print(f"  Tor Exit Node  : {'Yes' if abuse['is_tor'] else 'No'}")
        if abuse['last_reported']:
            print(f"  Last Reported  : {abuse['last_reported'][:10]}")

        if abuse['top_categories']:
            print(f"\n  Top Attack Types:")
            for name, count in abuse['top_categories'][:5]:
                print(f"    {name:<25} {count} report(s)")

        if abuse['reports']:
            print(f"\n  Recent Reports:")
            _firewall_words   = {'ttl', 'ufw', 'tos', 'packet', 'port'}
            _threat_keywords  = {'malware', 'phishing', 'ransomware', 'trojan', 'botnet', 'actor'}
            for r in abuse['reports']:
                date = r['reported_at'][:10] if r['reported_at'] else '?'
                cats = ', '.join(r['categories']) if r['categories'] else 'None'
                print(f"    [{date}] {cats}")
                comment = (r['comment'] or '').strip()
                if comment:
                    lower = comment.lower()
                    is_firewall = any(w in lower for w in _firewall_words)
                    has_domain  = '.' in comment and not comment.replace('.', '').replace(':', '').replace('/', '').replace(' ', '').isdigit()
                    has_threat  = any(k in lower for k in _threat_keywords)
                    if not is_firewall and (has_domain or has_threat):
                        print(f"             {comment[:80]}")

    # Score breakdown and verdict
    verdict_result = combined_verdict(vt, otx, abuse, config=config)

    print(f"\n  Score Breakdown:")
    for line in verdict_result["breakdown"]:
        print(f"    {line}")
    print(f"  {'─'*40}")
    print(f"\n  Verdict        : {verdict_result['final_verdict_display']}  (score: {verdict_result['score']})")
    print(f"  Recommendation : {verdict_result['recommendation']}")
    print(f"  Consensus      : {verdict_result['consensus_ratio']}")
    print(f"  Confidence     : {verdict_result['confidence']} (source)  |  {verdict_result['system_confidence']} (system)")
    print(f"  Triggered      : {', '.join(verdict_result['triggered_by'])}")
    print(f"  Mode           : {verdict_result['mode']}")
    print(f"  Active sources : {', '.join(verdict_result['active_sources'])}")
    if verdict_result['inactive_sources']:
        print(f"  No data from   : {', '.join(verdict_result['inactive_sources'])}")
    print()
    print(f"  Per Source:")
    for name, s in verdict_result['per_source'].items():
        print(f"    {name:<12}: {s['verdict_display']}  (confidence: {s['confidence']}, evidence: {s['evidence_count']})")
    print(f"  Contribution   :")
    for name, pct in verdict_result['contribution'].items():
        print(f"    {name:<12}: {pct}")
    print(f"{'='*45}\n")

    return verdict_result


def check_indicator(indicator):

    ind_type = detect_type(indicator)

    if ind_type is None:
        print("Invalid indicator. Enter a valid IPv4, domain, or hash.")
        return

    vt    = vt_check(indicator, ind_type)
    otx   = otx_check(indicator, ind_type)
    abuse = abuseipdb_check(indicator, ind_type)

    verdict_result = display_report(indicator, ind_type, vt, otx, abuse)
    save_results(indicator, vt, otx, verdict_result["final_verdict"])


# Main loop

while True:
    indicator = input("Enter IP, domain, or file hash (or 'exit' to quit, 'history' to view past lookups): ").strip()

    if indicator.lower() in ("exit", "quit", "q"):
        break

    parts = indicator.split()
    if parts and parts[0].lower() == "history":
        if len(parts) == 1:
            print_history()
        elif len(parts) == 2 and parts[1].isdigit():
            n     = int(parts[1])
            entry = get_history_entry(n)
            if entry is None:
                total = get_history_count()
                print(f"  Entry #{n} not found. History has {total} entries.")
            else:
                ind_type = detect_type(entry["indicator"])
                print(f"  (Cached result from {entry['timestamp']})")
                display_report(entry["indicator"], ind_type, entry["vt"], entry["otx"], None)
        else:
            print("  Usage: history  or  history <number>")
        continue

    check_indicator(indicator)
