import datetime
import json

def load_config(path="config.json"):
    with open(path) as f:
        config = json.load(f)

    scoring   = config["_meta"]["scoring"]
    aliases   = config.get("vt_engine_name_aliases", {})
    tier1_raw = config["tier1"]["vendors"]
    tier2_raw = config["tier2"]["vendors"]

    # Build alias lookup: vt_engine_name (lower) → canonical name (lower)
    alias_lookup = {}
    for canonical, vt_names in aliases.items():
        if isinstance(vt_names, list):
            for vt_name in vt_names:
                alias_lookup[vt_name.lower()] = canonical.lower()

    tier1 = set(v.lower() for v in tier1_raw)
    tier2 = set(v.lower() for v in tier2_raw)

    # Flatten nested tag_weights into a single {tag: weight} dict
    raw_tags    = config.get("tag_weights", {})
    tag_cap     = raw_tags.get("tag_cap", 5)
    tag_weights = {}
    for group, entries in raw_tags.items():
        if group.startswith("_") or group == "tag_cap":
            continue
        if isinstance(entries, dict):
            for tag, weight in entries.items():
                if not tag.startswith("_"):
                    tag_weights[tag.lower()] = weight

    return {
        "tier1":        tier1,
        "tier2":        tier2,
        "alias_lookup": alias_lookup,
        "scoring":      scoring,
        "tag_weights":  tag_weights,
        "tag_cap":      tag_cap,
        "default_mode": config.get("default_verdict_mode", "worst_case"),
        "apt_actors":   {a.lower() for a in config.get("apt_actors", [])},
    }


def resolve_vendor(raw_name, alias_lookup):
    return alias_lookup.get(raw_name.lower(), raw_name.lower())

# Used to pick the strongest confidence/verdict when comparing across sources
CONFIDENCE_ORDER = {None: 0, "low": 1, "medium": 2, "high": 3}

VERDICT_ORDER = {None: 0, "no_data": 0, "clean": 1, "suspicious": 2, "low_risk": 3, "medium_risk": 4, "high": 5}

VERDICT_DISPLAY = {
    "high":        "🔴 High risk",
    "medium_risk": "🟠 Medium risk",
    "low_risk":    "🟡 Low risk",
    "suspicious":  "⚠️  Suspicious",
    "clean":       "✅ Clean",
    "no_data":     "ℹ️  No data",
}

RECOMMENDATIONS = {
    "high":        "Escalate immediately",
    "medium_risk": "Investigate",
    "elevated":    "Review",
    "suspicious":  "Monitor",
    "clean":       "No action required",
    "no_data":     "No data available",
}

# OTX pulse tags that indicate automated scanner/honeypot noise, not real threat intel
NOISE_TAGS = {"honeypot", "tpot", "sensor-tagged", "scanner", "portscan", "scanners"}

def score_to_verdict(score):
    # Thresholds: <=0=clean, 1-2=suspicious, 3-4=low, 5-7=medium, 8+=high
    if score <= 0:
        return "clean"
    elif score <= 2:
        return "suspicious"
    elif score <= 4:
        return "low_risk"
    elif score <= 7:
        return "medium_risk"
    else:
        return "high"


def score_vt(vt, config):
    """Score VirusTotal data. Returns per-source result dict.

    Scoring layers (additive, capped at 15):
      1. Raw malicious count  — how many engines flagged it
      2. Harmless deduction   — counterbalances noise when most engines agree it's clean
      3. Suspicious count     — engines that hedged rather than flagged outright
      4. Vendor tier hits     — weighted by engine reputation (tier1 > tier2 > tier3)
      5. Tags                 — VT behavioral tags (e.g. 'miner', 'trojan') from config weights
      6. Recency              — recent scans with hits are more actionable than old ones
    """

    if not vt:
        return {"verdict": "no_data", "confidence": None, "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": []}

    score        = 0
    breakdown    = []
    tier1        = config["tier1"]
    tier2        = config["tier2"]
    alias_lookup = config["alias_lookup"]
    scoring      = config["scoring"]

    malicious  = vt.get("malicious", 0)
    harmless   = vt.get("harmless", 0)
    undetected = vt.get("undetected", 0)

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

    # Deduct when an overwhelming majority of engines agree the IP is clean.
    # The malicious guard prevents deductions on IPs that still have detections.
    if harmless >= 50 and malicious <= 1:
        score -= 2
        breakdown.append(f"Harmless majority {harmless:<4}  → -2  (overwhelmingly clean)")
    elif harmless >= 30 and malicious <= 2:
        score -= 1
        breakdown.append(f"Harmless majority {harmless:<4}  → -1  (mostly clean)")

    suspicious = vt.get("suspicious", 0)

    if suspicious >= 3:
        score += 1
        breakdown.append(f"Suspicious count {suspicious:<4} → +1")
    else:
        breakdown.append(f"Suspicious count {suspicious:<4} → +0")

    tier1_hits = tier2_hits = tier3_hits = 0

    # Classify each flagging vendor by tier after resolving any VT engine name aliases
    for v in vt.get("malicious_vendors", []):
        canonical = resolve_vendor(v["vendor"], alias_lookup)
        if canonical in tier1:
            tier1_hits += 1
        elif canonical in tier2:
            tier2_hits += 1
        else:
            tier3_hits += 1

    # Per-tier points are capped independently so a flood of low-tier hits can't dominate
    tier1_points = min(tier1_hits * scoring["tier1_points"], scoring["tier1_cap"])
    tier2_points = min(tier2_hits * scoring["tier2_points"], scoring["tier2_cap"])
    tier3_points = min(tier3_hits * scoring["tier3_points"], scoring["tier3_cap"])

    score += tier1_points + tier2_points + tier3_points

    if tier1_hits > 0:
        breakdown.append(f"Tier 1 vendors   {tier1_hits:<5} → +{tier1_points}  (cap {scoring['tier1_cap']})")
    if tier2_hits > 0:
        breakdown.append(f"Tier 2 vendors   {tier2_hits:<5} → +{tier2_points}  (cap {scoring['tier2_cap']})")
    if tier3_hits > 0:
        breakdown.append(f"Tier 3 vendors   {tier3_hits:<5} → +{tier3_points}  (cap {scoring['tier3_cap']})")

    tag_score  = 0
    found_tags = []

    for tag in vt.get("tags", []):
        weight = config["tag_weights"].get(tag.lower(), 0)
        if weight > 0:
            tag_score += weight
            found_tags.append(tag)

    tag_score = min(tag_score, config["tag_cap"])
    score += tag_score

    if found_tags:
        breakdown.append(f"Tags {', '.join(found_tags):<20} → +{tag_score}  (cap {config['tag_cap']})")
    else:
        breakdown.append(f"Tags none                    → +0")

    # Recency only applies when there are active malicious detections — an old clean scan
    # shouldn't penalize an IP, and a brand-new scan of a clean IP isn't worth boosting.
    if vt.get("last_scan_date") and malicious > 0:
        now       = datetime.datetime.now()
        scan_date = datetime.datetime.fromtimestamp(vt["last_scan_date"])
        days_ago  = (now - scan_date).days

        if days_ago <= 7:
            score += 2
            breakdown.append(f"Last scanned {days_ago} days ago       → +2")
        elif days_ago <= 30:
            score += 1
            breakdown.append(f"Last scanned {days_ago} days ago       → +1")
        elif days_ago > 180:
            # Stale detections are less actionable; slight deduction to avoid over-alerting
            score -= 1
            breakdown.append(f"Last scanned {days_ago} days ago       → -1  (old)")
        else:
            breakdown.append(f"Last scanned {days_ago} days ago       → +0")
    else:
        if vt.get("last_scan_date"):
            breakdown.append(f"Recency skipped — no malicious detections")

    # Only assign a real verdict if there's something to judge; avoids false "clean" on empty responses
    has_data = (
        malicious > 0 or
        suspicious > 0 or
        len(found_tags) > 0 or
        harmless > 0 or
        undetected > 0
    )

    if malicious >= 10:
        confidence = "high"
    elif malicious >= 4:
        confidence = "medium"
    elif malicious >= 1:
        confidence = "low"
    elif harmless >= 10:
        confidence = "high"    # many engines scanned and agreed it's clean
    elif harmless >= 1:
        confidence = "medium"
    else:
        confidence = None

    score = min(score, 15)

    verdict = score_to_verdict(score) if has_data else "no_data"

    return {
        "verdict":        verdict,
        "confidence":     confidence,
        "score":          score,
        "evidence_count": malicious,
        "has_data":       has_data,
        "breakdown":      breakdown,
    }


def score_otx(otx, vt_score=0, config=None):
    """Score AlienVault OTX data. Returns per-source result dict.

    Most OTX signals are gated behind vt_score >= 1: pulses, recency, tags, and passive DNS
    are only counted when VT has already flagged something. OTX alone has too many false
    positives because pulses are community-submitted with no vetting process.

    Exceptions (fire without the VT gate):
      - Adversary attribution: named APT/adversary fields are high-signal regardless of VT
      - Malware families: a named family in a pulse is strong enough to stand alone
    """
    # OTX pulses and passive DNS are only counted when VT already flagged something;
    # OTX alone has too many false positives (pulses get added by anyone in the community)

    if not otx:
        return {"verdict": "no_data", "confidence": None, "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": []}

    score     = 0
    breakdown = []

    pulse_count = otx.get("pulse_count", 0)

    if vt_score >= 1:
        if pulse_count >= 10:
            score += 2
            breakdown.append(f"OTX pulses {pulse_count:<8} → +2  (widely tracked)")
        elif pulse_count >= 1:
            score += 1
            breakdown.append(f"OTX pulses {pulse_count:<8} → +1")
        else:
            breakdown.append(f"OTX pulses {pulse_count:<8} → +0")
    else:
        breakdown.append(f"OTX pulses {pulse_count:<8} → +0  (skipped — no VT detections)")

    reputation = otx.get("reputation", 0)

    if reputation < 0:
        score += 1
        breakdown.append(f"OTX reputation {reputation:<5} → +1  (negative)")
    else:
        breakdown.append(f"OTX reputation {reputation:<5} → +0")

    # Single pass over pulse_details: noise filter, recency, tag scoring, adversary, families
    pulse_tag_score    = 0
    pulse_tag_contrib  = {}
    adversary_score    = 0
    apt_hit            = False
    family_score       = 0
    recent_pulse_found = False

    for p in otx.get("pulse_details", []):
        p_tags = {t.lower() for t in p.get("tags", [])}

        # Skip pulses whose tags are entirely noise (honeypots, scanners, etc.)
        if p_tags and p_tags.issubset(NOISE_TAGS):
            continue

        # OTX doesn't expose a reliable created_at field via the indicator API,
        # so we look for the year in the pulse name as a cheap recency heuristic.
        if "2026" in p.get("name", "") or "2025" in p.get("name", ""):
            recent_pulse_found = True

        # Pulse tag scoring (gated — pulse tags are as noisy as pulses themselves)
        if vt_score >= 1 and config:
            for tag in p_tags - NOISE_TAGS:
                w = config["tag_weights"].get(tag, 0)
                if w > 0:
                    pulse_tag_score += w
                    pulse_tag_contrib[tag] = pulse_tag_contrib.get(tag, 0) + w

        # Adversary attribution is high-signal regardless of VT
        adversary = p.get("adversary", "")
        if adversary:
            apt_actors = config.get("apt_actors", set()) if config else set()
            if adversary.lower() in apt_actors:
                adversary_score = min(adversary_score + 4, 4)
                apt_hit = True
            else:
                adversary_score = min(adversary_score + 2, 4)

        # Malware family is high-signal — fires without the VT gate
        if p.get("families", []):
            family_score = min(family_score + 2, 4)

    if vt_score >= 1:
        if recent_pulse_found:
            score += 1
            breakdown.append(f"Recent pulse (2025/2026)     → +1")
        else:
            breakdown.append(f"Recent pulse (2025/2026)     → +0")
    else:
        breakdown.append(f"Recent pulse                 → +0  (skipped — no VT detections)")

    if vt_score >= 1:
        pulse_tag_score = min(pulse_tag_score, 5)
        if pulse_tag_contrib:
            score += pulse_tag_score
            for tag, w in sorted(pulse_tag_contrib.items(), key=lambda x: -x[1]):
                breakdown.append(f"  Pulse tag [{tag}] → +{w}")
            breakdown.append(f"Pulse tags (capped)          → +{pulse_tag_score}  (cap 5)")
        else:
            breakdown.append(f"Pulse tags                   → +0")
    else:
        breakdown.append(f"Pulse tags                   → +0  (skipped — no VT detections)")

    if adversary_score > 0:
        score += adversary_score
        label = "APT actor" if apt_hit else "adversary"
        breakdown.append(f"Adversary attribution ({label}) → +{adversary_score}  (cap 4)")
    else:
        breakdown.append(f"Adversary attribution        → +0")

    if family_score > 0:
        score += family_score
        breakdown.append(f"Malware families             → +{family_score}  (cap 4)")
    else:
        breakdown.append(f"Malware families             → +0")

    pdns        = otx.get("passive_dns", [])
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

    if vt_score >= 1:
        if latest_pdns:
            days_since = (datetime.datetime.now() - latest_pdns).days
            if days_since <= 30:
                score += 1
                breakdown.append(f"Passive DNS last seen {days_since} days ago → +1")
            else:
                breakdown.append(f"Passive DNS last seen {days_since} days ago → +0")
        else:
            breakdown.append(f"Passive DNS last seen unknown  → +0")
    else:
        breakdown.append(f"Passive DNS                  → +0  (skipped — no VT detections)")

    score = min(score, 15)

    # reputation is 0 for unknown IPs, negative means OTX community flagged it
    has_data = pulse_count > 0 or reputation < 0

    if pulse_count >= 10 or adversary_score > 0 or family_score > 0:
        confidence = "high"
    elif pulse_count >= 1 or pulse_tag_score > 0:
        confidence = "medium"
    else:
        confidence = None

    verdict = score_to_verdict(score) if has_data else "no_data"

    return {
        "verdict":        verdict,
        "confidence":     confidence,
        "score":          score,
        "evidence_count": pulse_count,
        "has_data":       has_data,
        "breakdown":      breakdown,
    }


def score_abuse(abuse):
    """Score AbuseIPDB data. Returns per-source result dict.

    Scoring layers (additive, capped at 15):
      1. Abuse confidence score — AbuseIPDB's own 0-100 percentage
      2. Distinct reporters     — independent sources corroborate the abuse (skipped when score is 0)
      3. Recency                — recent reports are more actionable; stale reports are penalized
      4. Tor exit node          — anonymization proxy adds baseline risk
    """

    if not abuse:
        return {"verdict": "no_data", "confidence": None, "score": 0,
                "evidence_count": 0, "has_data": False, "breakdown": []}

    score          = 0
    breakdown      = []
    abuse_score    = abuse.get("abuse_score", 0)
    distinct_users = abuse.get("distinct_users", 0)
    is_tor         = abuse.get("is_tor", False)

    if abuse_score >= 80:
        score += 3
        breakdown.append(f"AbuseIPDB score {abuse_score:<5}  → +3  (high confidence)")
    elif abuse_score >= 40:
        score += 2
        breakdown.append(f"AbuseIPDB score {abuse_score:<5}  → +2  (moderate)")
    elif abuse_score >= 10:
        score += 1
        breakdown.append(f"AbuseIPDB score {abuse_score:<5}  → +1  (low)")
    else:
        breakdown.append(f"AbuseIPDB score {abuse_score:<5}  → +0")

    if abuse_score == 0:
        breakdown.append(f"Distinct reporters {distinct_users:<3}    → +0  (skipped — AbuseIPDB confidence 0%)")
    elif distinct_users >= 50:
        score += 2
        breakdown.append(f"Distinct reporters {distinct_users:<3}    → +2  (widely reported)")
    elif distinct_users >= 10:
        score += 1
        breakdown.append(f"Distinct reporters {distinct_users:<3}    → +1")
    else:
        breakdown.append(f"Distinct reporters {distinct_users:<3}    → +0")

    last_reported = abuse.get("last_reported")
    if last_reported:
        try:
            last_dt  = datetime.datetime.fromisoformat(last_reported[:19])
            days_ago = (datetime.datetime.now() - last_dt).days
            if days_ago <= 7:
                score += 1
                breakdown.append(f"Last reported {days_ago} days ago       → +1")
            elif days_ago > 180:
                score -= 1
                breakdown.append(f"Last reported {days_ago} days ago       → -1  (old)")
            else:
                breakdown.append(f"Last reported {days_ago} days ago       → +0")
        except (ValueError, TypeError):
            breakdown.append(f"Last reported date unknown  → +0")
    else:
        breakdown.append(f"Last reported unknown        → +0")

    if is_tor:
        score += 1
        breakdown.append(f"Tor exit node               → +1")
    else:
        breakdown.append(f"Tor exit node               → +0")

    has_data = abuse_score > 0 or distinct_users > 0 or is_tor

    if abuse_score >= 80 or distinct_users >= 50:
        confidence = "high"
    elif abuse_score >= 40 or distinct_users >= 10:
        confidence = "medium"
    elif abuse_score >= 10:
        confidence = "low"
    else:
        confidence = None

    score = min(score, 15)

    verdict = score_to_verdict(score) if has_data else "no_data"

    return {
        "verdict":        verdict,
        "confidence":     confidence,
        "score":          score,
        "evidence_count": distinct_users,
        "has_data":       has_data,
        "breakdown":      breakdown,
    }


def combined_verdict(vt, otx, abuse=None, mode=None, config=None):
    """Combine per-source scores into a single final verdict.

    Three aggregation modes (set via config or overridden per-call):
      worst_case  — takes the highest verdict across all active sources; most conservative
      average     — averages raw scores then maps to a verdict; balances all sources equally
      weighted    — blends verdicts using fixed source weights (VT 50%, OTX 30%, Abuse 20%),
                    normalizing to the active subset so missing sources don't dilute the result

    Confidence is derived from corroboration (how many sources agree on the final verdict)
    rather than from any individual source, because cross-source agreement is a stronger
    signal than a single high-confidence hit.
    """

    if config is None:
        config = load_config()

    if mode is None:
        mode = config.get("default_mode", "worst_case")

    vt_result    = score_vt(vt, config)
    otx_result   = score_otx(otx, vt_score=vt_result["score"], config=config)
    abuse_result = score_abuse(abuse)

    sources = {
        "VirusTotal": vt_result,
        "OTX":        otx_result,
        "AbuseIPDB":  abuse_result,
    }

    # Only include sources that returned real data so no-data sources don't drag the verdict down
    active = {name: r for name, r in sources.items() if r["has_data"]}

    if not active:
        return {
            "final_verdict":         "no_data",
            "final_verdict_display": VERDICT_DISPLAY["no_data"],
            "confidence":            None,
            "triggered_by":          [],
            "mode":                  mode,
            "score":                 0,
            "corroboration_count":   0,
            "consensus_ratio":       "Weak (0/0)",
            "recommendation":        RECOMMENDATIONS["no_data"],
            "per_source": {
                name: {
                    "verdict":         r["verdict"],
                    "verdict_display": VERDICT_DISPLAY.get(r["verdict"], r["verdict"]),
                    "confidence":      r["confidence"],
                    "score":           r["score"],
                    "evidence_count":  r["evidence_count"],
                    "has_data":        r["has_data"],
                }
                for name, r in sources.items()
            },
            "breakdown": [],
        }

    if mode == "worst_case":
        final_verdict = max(
            (r["verdict"] for r in active.values()),
            key=lambda v: VERDICT_ORDER.get(v, 0)
        )

    elif mode == "average":
        avg_score = sum(r["score"] for r in active.values()) / len(active)
        final_verdict = score_to_verdict(avg_score)

    elif mode == "weighted":
        base_weights       = {"VirusTotal": 0.5, "OTX": 0.3, "AbuseIPDB": 0.2}
        active_weights     = {name: base_weights.get(name, 0.1) for name in active}
        total_weight       = sum(active_weights.values())
        # Renormalize so the weights of active sources always sum to 1.0,
        # preventing a missing source from artificially lowering the blended score.
        normalized_weights = {name: w / total_weight for name, w in active_weights.items()}
        weighted_sum       = sum(
            VERDICT_ORDER[r["verdict"]] * normalized_weights[name]
            for name, r in active.items()
        )
        valid_verdicts = ["clean", "suspicious", "low_risk", "medium_risk", "high"]
        # Pick the highest verdict that doesn't exceed the weighted sum (floor, not round)
        final_verdict = max(
            valid_verdicts,
            key=lambda v: VERDICT_ORDER[v] if VERDICT_ORDER[v] <= weighted_sum else -1
        )

    else:
        # Unknown mode — fall back to worst_case to avoid silently under-reporting
        final_verdict = max(
            (r["verdict"] for r in active.values()),
            key=lambda v: VERDICT_ORDER.get(v, 0)
        )

    triggered_by        = [name for name, r in active.items() if r["verdict"] == final_verdict]
    corroboration_count = len(triggered_by)

    # More sources agreeing → higher confidence, regardless of individual source confidence
    if corroboration_count >= 3:
        confidence = "high"
    elif corroboration_count >= 2:
        confidence = "medium"
    else:
        # Single source: fall back to that source's own confidence level
        source_confidences = [r["confidence"] for r in active.values() if r["confidence"]]
        if source_confidences:
            confidence = max(source_confidences, key=lambda c: CONFIDENCE_ORDER[c])
        else:
            confidence = "low"

    active_count = len(active)
    ratio_str    = f"{corroboration_count}/{active_count}"
    if corroboration_count == active_count:
        consensus_ratio = f"Strong ({ratio_str})"
    elif corroboration_count >= 2:
        consensus_ratio = f"Moderate ({ratio_str})"
    else:
        consensus_ratio = f"Weak ({ratio_str})"

    full_breakdown = []
    for name, r in sources.items():
        if r["breakdown"]:
            full_breakdown.append(f"── {name} ──")
            full_breakdown.extend(r["breakdown"])

    total_score = sum(r["score"] for r in active.values())

    return {
        "final_verdict":         final_verdict,
        "final_verdict_display": VERDICT_DISPLAY.get(final_verdict, final_verdict),
        "confidence":            confidence,
        "triggered_by":          triggered_by,
        "mode":                  mode,
        "score":                 total_score,
        "corroboration_count":   corroboration_count,
        "consensus_ratio":       consensus_ratio,
        "recommendation":        RECOMMENDATIONS.get(final_verdict, "Review"),
        "per_source": {
            name: {
                "verdict":         r["verdict"],
                "verdict_display": VERDICT_DISPLAY.get(r["verdict"], r["verdict"]),
                "confidence":      r["confidence"],
                "score":           r["score"],
                "evidence_count":  r["evidence_count"],
                "has_data":        r["has_data"],
            }
            for name, r in sources.items()
        },
        "breakdown": full_breakdown,
    }
