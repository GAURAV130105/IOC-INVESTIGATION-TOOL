import datetime

from detect import detect_type
from sources.vt import vt_check
from sources.otx import otx_check
from sources.shodan import shodan_check
from sources.abuseipdb import abuseipdb_check
from sources.whois import whois_check
from sources.scoring import combined_verdict, load_config, resolve_vendor, VERDICT_DISPLAY
from cache import clear_cache, clear_indicator_cache
from output import save_results, print_history, get_history_entry, get_history_count, clear_history, clear_indicator, get_last_result, compare_results


config = load_config("config.json")
VERBOSE = False


def display_report(indicator, ind_type, vt, otx, abuse, shodan=None, whois=None):

    verdict_result = combined_verdict(vt, otx, abuse, shodan, whois=whois, config=config)

    if not VERBOSE:
        print(f"\n{'='*45}")
        print(f"  Threat Report: {indicator}")
        print(f"{'='*45}")

        # VirusTotal summary line
        if vt:
            malicious = vt['malicious']
            harmless  = vt['harmless']
            if malicious == 0:
                tier_summary = "clean"
            else:
                tier1_hits = tier2_hits = 0
                for v in vt.get("malicious_vendors", []):
                    canonical = resolve_vendor(v["vendor"], config["alias_lookup"])
                    if canonical in config["tier1"]:
                        tier1_hits += 1
                    elif canonical in config["tier2"]:
                        tier2_hits += 1
                if tier1_hits > 0:
                    tier_summary = "includes Tier 1"
                elif tier2_hits > 0:
                    tier_summary = "includes Tier 2"
                else:
                    tier_summary = "Tier 3 only"
            print(f"\n  [VirusTotal]    {malicious} malicious / {harmless} harmless — {tier_summary}")
        else:
            print(f"\n  [VirusTotal]    no data")

        # OTX summary line
        if otx:
            pulse_count   = otx['pulse_count']
            pulse_details = otx.get("pulse_details", [])
            adversary     = next((p["adversary"] for p in pulse_details if p.get("adversary")), None)
            family        = next((p["families"][0] for p in pulse_details if p.get("families")), None)
            if adversary:
                top_signal = f"APT: {adversary}"
            elif family:
                top_signal = f"family: {family}"
            elif pulse_count > 0:
                top_signal = f"{pulse_count} pulses"
            else:
                top_signal = "no data"
            print(f"  [OTX]           {pulse_count} pulses — {top_signal}")
        else:
            print(f"  [OTX]           no data")

        # AbuseIPDB summary line
        if not abuse or (abuse.get('total_reports', 0) == 0 and
                         abuse.get('distinct_users', 0) == 0 and
                         not abuse.get('is_tor', False)):
            abuse_summary = "no data"
        else:
            abuse_summary = f"{abuse['total_reports']} reports, {abuse['distinct_users']} users"
        print(f"  [AbuseIPDB]     {abuse_summary}")

        # Shodan summary line
        if shodan:
            org = shodan.get('org') or 'Unknown'
            asn = (shodan.get('asn') or '').strip().upper()
            if asn in config.get('cdn_asns', {}):
                print(f"  [Shodan]        {org} (CDN — port/hostname/product scoring skipped)")
            elif asn in config.get('cloud_hosting_asns', {}):
                print(f"  [Shodan]        {org} (cloud hosting — port/hostname scoring skipped)")
            else:
                ports     = shodan.get('ports', [])
                ports_str = ', '.join(str(p) for p in ports) if ports else "no suspicious findings"
                print(f"  [Shodan]        {org} — {ports_str}")
        else:
            print(f"  [Shodan]        no data")

        # WHOIS summary line
        if whois:
            age_days  = whois.get('domain_age_days')
            age_str   = f"{age_days} days old" if age_days is not None else "unknown age"
            registrar = (whois.get('registrar') or 'unknown registrar')[:35]
            print(f"  [WHOIS]         {whois.get('domain', indicator)} — {age_str}, {registrar}")
        else:
            print(f"  [WHOIS]         no data")

        print(f"\n  Verdict        : {verdict_result['final_verdict_display']}")
        print(f"  Recommendation : {verdict_result['recommendation']}")
        print(f"  Triggered by   : {', '.join(verdict_result['triggered_by'])}")
        _whois_ctx = verdict_result.get('whois_context', {})
        if _whois_ctx.get('has_data'):
            print(f"  Supporting     : WHOIS (+{_whois_ctx['score_modifier']} domain context)")
        print(f"  Consensus      : {verdict_result['consensus_ratio']}")
        print(f"{'='*45}\n")

    else:
        # Verbose: full source detail + score breakdown
        print(f"\n{'='*45}")
        print(f"  Threat Report: {indicator}")
        print(f"{'='*45}")

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
                print(f"\n  Passive DNS ({len(pdns)} record(s), showing first 5):")
                for r in pdns[:5]:
                    first = r["first"][:10] if r["first"] else "?"
                    last  = r["last"][:10]  if r["last"]  else "?"
                    print(f"    [{r['record_type']:<5}] {r['hostname'] or r['address']:<40}  first: {first}  last: {last}")

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
                _firewall_words  = {'ttl', 'ufw', 'tos', 'packet', 'port'}
                _threat_keywords = {'malware', 'phishing', 'ransomware', 'trojan', 'botnet', 'actor'}
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

        if shodan:
            print(f"\n  [Shodan]")
            print(f"  Org          : {shodan['org']}")
            print(f"  ISP          : {shodan['isp']}")
            print(f"  ASN          : {shodan['asn']}")
            print(f"  OS           : {shodan['os'] or 'Unknown'}")
            print(f"  Last scan    : {shodan['last_update'][:10] if shodan['last_update'] else 'Unknown'}")

            if shodan['hostnames']:
                print(f"  Hostnames    : {', '.join(shodan['hostnames'][:3])}")
            else:
                print(f"  Hostnames    : None")

            if shodan['ports']:
                print(f"  Open ports   : {', '.join(str(p) for p in shodan['ports'])}")

            if shodan['tags']:
                print(f"  Tags         : {', '.join(shodan['tags'])}")

            if shodan['vulns']:
                print(f"\n  CVEs ({len(shodan['vulns'])} found):")
                for cve in shodan['vulns'][:5]:
                    print(f"    {cve}")

            if shodan['services']:
                print(f"\n  Services:")
                for svc in shodan['services']:
                    product = svc['product'] or 'Unknown'
                    version = svc['version'] or ''
                    label   = f"{product} {version}".strip()
                    print(f"    Port {svc['port']:<6} {svc['transport']:<4} {label}")

        if whois:
            print(f"\n  [WHOIS]")
            print(f"  Domain         : {whois.get('domain') or 'N/A'}")
            print(f"  Registrar      : {whois.get('registrar') or 'N/A'}")
            creation = whois.get('creation_date')
            print(f"  Creation date  : {creation[:10] if creation else 'N/A'}")
            age_days = whois.get('domain_age_days')
            print(f"  Domain age     : {age_days} days" if age_days is not None else "  Domain age     : unknown")
            expiry = whois.get('expiration_date')
            print(f"  Expiration     : {expiry[:10] if expiry else 'N/A'}")
            print(f"  Privacy masked : {'Yes' if whois.get('privacy_masked') else 'No'}")
            print(f"  Country        : {whois.get('country') or 'N/A'}")
            ns = whois.get('name_servers', [])
            print(f"  Name servers   : {', '.join(ns[:3]) if ns else 'N/A'}")

        print(f"\n  Per Source:")
        for name, s in verdict_result['per_source'].items():
            print(f"    {name:<12}: {s['verdict_display']}  (evidence: {s['evidence_count']})")

        print(f"\n  Score Breakdown:")
        for line in verdict_result["breakdown"]:
            print(f"    {line}")
        print(f"  {'─'*40}")

        print(f"\n  Contribution   :")
        for name, pct in verdict_result['contribution'].items():
            print(f"    {name:<12}: {pct}")

        print(f"\n  Verdict        : {verdict_result['final_verdict_display']}  (avg score: {verdict_result['score']})")
        print(f"  Recommendation : {verdict_result['recommendation']}")
        print(f"  Consensus      : {verdict_result['consensus_ratio']}")
        print(f"  Triggered      : {', '.join(verdict_result['triggered_by'])}")
        _whois_ctx = verdict_result.get('whois_context', {})
        if _whois_ctx.get('has_data'):
            print(f"  Supporting     : WHOIS (+{_whois_ctx['score_modifier']} domain context)")
        print(f"  Active sources : {', '.join(verdict_result['active_sources'])}")
        if verdict_result['inactive_sources']:
            print(f"  No data from   : {', '.join(verdict_result['inactive_sources'])}")
        print(f"{'='*45}\n")

    return verdict_result


def _print_changes(changes, since_ts):
    if not changes:
        print(f"  ✓  No changes since last scan ({since_ts})\n")
        return
    print(f"\n  ⚠️  Changes since last scan ({since_ts}):")
    if "verdict" in changes:
        old_v = VERDICT_DISPLAY.get(changes["verdict"]["from"], changes["verdict"]["from"] or "no data")
        new_v = VERDICT_DISPLAY.get(changes["verdict"]["to"],   changes["verdict"]["to"]   or "no data")
        print(f"    Verdict  : {old_v} → {new_v}")
    if "score" in changes:
        print(f"    Score    : {changes['score']['from']} → {changes['score']['to']}")
    if "sources" in changes:
        for src, chg in changes["sources"].items():
            old_v = VERDICT_DISPLAY.get(chg["from"], chg["from"] or "no data")
            new_v = VERDICT_DISPLAY.get(chg["to"],   chg["to"]   or "no data")
            print(f"    {src:<12}: {old_v} → {new_v}")
    print()


def check_indicator(indicator, previous=None):

    ind_type = detect_type(indicator)

    if ind_type is None:
        print("Invalid indicator. Enter a valid IPv4, domain, or hash.")
        return

    old_entry = previous if previous is not None else get_last_result(indicator)

    vt     = vt_check(indicator, ind_type)
    otx    = otx_check(indicator, ind_type)
    abuse  = abuseipdb_check(indicator, ind_type)
    shodan = shodan_check(indicator, ind_type)
    whois  = whois_check(indicator, ind_type)

    verdict_result = display_report(indicator, ind_type, vt, otx, abuse, shodan, whois)
    save_results(indicator, vt, otx, abuse, shodan, verdict_result["final_verdict"], whois,
                 score=verdict_result["score"], per_source=verdict_result["per_source"])

    if old_entry is not None:
        new_cmp = {
            "verdict":    verdict_result["final_verdict"],
            "score":      verdict_result["score"],
            "per_source": verdict_result["per_source"],
        }
        _print_changes(compare_results(old_entry, new_cmp), old_entry["timestamp"])


# Main loop

print("╔══════════════════════════════════════════════╗")
print("║         IOC Investigation Tool               ║")
print("╠══════════════════════════════════════════════╣")
print("║  Enter an IP, domain, or file hash           ║")
print("║  Type 'help' for available commands          ║")
print("╚══════════════════════════════════════════════╝")

while True:
    indicator = input("\n> ").strip()

    if indicator.lower() in ("exit", "quit", "q"):
        break

    if indicator.lower() == "help":
        print(f"""
  Commands
  ────────────────────────────────────────
  history              List past lookups
  history <n>          Replay lookup #n
  history clear        Delete all history

  verbose              Show full breakdown
  brief                Show summary only

  reset cache          Clear cached API results
  rescan <indicator>   Delete one IOC from history and cache, then rescan it
  exit                 Quit
  ────────────────────────────────────────
        """)
        continue

    if indicator.lower() == "verbose":
        VERBOSE = True
        print("  Verbose mode on — full breakdown will be shown.")
        continue

    if indicator.lower() == "brief":
        VERBOSE = False
        print("  Brief mode on — summary only.")
        continue

    parts = indicator.split()
    if parts and parts[0].lower() == "history":
        if len(parts) == 1:
            print_history()
        elif len(parts) == 2 and parts[1].lower() == "clear":
            confirm = input("  Clear all history? Type 'yes' to confirm: ").strip().lower()
            if confirm == "yes":
                clear_history()
                print("  History cleared.")
            else:
                print("  Cancelled.")
        elif len(parts) == 2 and parts[1].isdigit():
            n     = int(parts[1])
            entry = get_history_entry(n)
            if entry is None:
                total = get_history_count()
                print(f"  Entry #{n} not found. History has {total} entries.")
            else:
                ind_type = detect_type(entry["indicator"])
                print(f"  (Cached result from {entry['timestamp']})")
                display_report(entry["indicator"], ind_type, entry["vt"], entry["otx"], entry["abuse"], entry["shodan"], entry.get("whois"))
        else:
            print("  Usage: history  or  history <number>  or  history clear")
        continue

    if parts and " ".join(parts[:2]).lower() == "reset cache":
        confirm = input("  Clear all cached API results? Type 'yes' to confirm: ").strip().lower()
        if confirm == "yes":
            clear_cache()
            print("  API cache cleared.")
        else:
            print("  Cancelled.")
        continue

    if parts and parts[0].lower() == "rescan":
        if len(parts) < 2:
            print("  Usage: rescan <ip / domain / hash>")
            continue
        target = parts[1].strip()
        if detect_type(target) is None:
            print(f"  Invalid indicator: {target}")
            continue
        confirm = input(f"  Delete {target} from history and cache and rescan? Type 'yes' to confirm: ").strip().lower()
        if confirm != "yes":
            print("  Cancelled.")
            continue
        old_entry       = get_last_result(target)
        cache_deleted   = clear_indicator_cache(target)
        history_deleted = clear_indicator(target)
        print(f"  Cleared {cache_deleted} cache entries and {history_deleted} history entries for {target}")
        print(f"  Rescanning {target}...")
        check_indicator(target, previous=old_entry)
        continue

    check_indicator(indicator)
