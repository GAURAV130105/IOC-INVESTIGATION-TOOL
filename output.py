import sqlite3
import json
import datetime
import csv

from cache import DB_PATH
from detect import detect_type
from sources.scoring import VERDICT_DISPLAY


def print_history():
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, indicator, verdict
        FROM history
        ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("  No past lookups found.")
        return

    print(f"\n  {'─'*45}")
    print(f"  Past Lookups")
    print(f"  {'─'*45}")

    for i, (timestamp, indicator, verdict) in enumerate(rows, 1):
        display = VERDICT_DISPLAY.get(verdict, verdict)
        print(f"  {i}. {indicator:<20} {display:<20} {timestamp}")

    print(f"  {'─'*45}\n")


def init_history_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            indicator   TEXT NOT NULL UNIQUE,
            vt_result   TEXT,
            otx_result  TEXT,
            abuse_result TEXT,
            shodan_result TEXT,
            verdict     TEXT
        )
    """)
    conn.commit()
    for col, col_type in [("whois_result", "TEXT"), ("score", "REAL"), ("per_source", "TEXT")]:
        try:
            conn.execute(f"ALTER TABLE history ADD COLUMN {col} {col_type}")
            conn.commit()
        except sqlite3.OperationalError:
            pass
    conn.close()


def save_results(indicator, vt_result, otx_result, abuse_result, shodan_result, verdict, whois_result=None, score=None, per_source=None):
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO history (timestamp, indicator, vt_result, otx_result, abuse_result, shodan_result, verdict, whois_result, score, per_source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(indicator) DO UPDATE SET
            timestamp     = excluded.timestamp,
            vt_result     = excluded.vt_result,
            otx_result    = excluded.otx_result,
            abuse_result  = excluded.abuse_result,
            shodan_result = excluded.shodan_result,
            verdict       = excluded.verdict,
            whois_result  = excluded.whois_result,
            score         = excluded.score,
            per_source    = excluded.per_source
    """, (
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        indicator,
        json.dumps(vt_result),
        json.dumps(otx_result),
        json.dumps(abuse_result),
        json.dumps(shodan_result),
        verdict,
        json.dumps(whois_result),
        score,
        json.dumps(per_source) if per_source is not None else None,
    ))
    conn.commit()

    total = cursor.execute("SELECT COUNT(*) FROM history").fetchone()[0]
    conn.close()

    print(f"  Result saved to database ({total} total)")


def get_history_count():
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]
    conn.close()
    return total


def clear_history():
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM history")
    conn.commit()
    conn.close()


def clear_indicator(indicator):
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM history WHERE indicator = ?", (indicator,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted


def get_last_result(indicator):
    """Return the most recent history record for an indicator, or None."""
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, indicator, vt_result, otx_result, abuse_result, shodan_result, verdict, whois_result, score, per_source
        FROM history
        WHERE indicator = ?
        ORDER BY id DESC
        LIMIT 1
    """, (indicator,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    timestamp, ind, vt_json, otx_json, abuse_json, shodan_json, verdict, whois_json, score, per_source_json = row
    return {
        "timestamp":  timestamp,
        "indicator":  ind,
        "vt":         json.loads(vt_json) if vt_json else None,
        "otx":        json.loads(otx_json) if otx_json else None,
        "abuse":      json.loads(abuse_json) if abuse_json else None,
        "shodan":     json.loads(shodan_json) if shodan_json else None,
        "whois":      json.loads(whois_json) if whois_json else None,
        "verdict":    verdict,
        "score":      score,
        "per_source": json.loads(per_source_json) if per_source_json else {},
    }


def compare_results(old, new):
    """Return a dict of fields that changed between two result records."""
    changes = {}

    if old.get("verdict") != new.get("verdict"):
        changes["verdict"] = {
            "from": old.get("verdict"),
            "to":   new.get("verdict"),
        }

    old_score = old.get("score") or 0
    new_score = new.get("score") or 0
    if abs(new_score - old_score) > 1.0:
        changes["score"] = {
            "from": round(old_score, 1),
            "to":   round(new_score, 1),
        }

    old_sources = old.get("per_source") or {}
    new_sources = new.get("per_source") or {}
    source_changes = {}
    for source in new_sources:
        old_v = old_sources.get(source, {}).get("verdict", "no_data")
        new_v = new_sources.get(source, {}).get("verdict", "no_data")
        if old_v != new_v:
            source_changes[source] = {"from": old_v, "to": new_v}
    if source_changes:
        changes["sources"] = source_changes

    return changes


def export_csv(output_path="results.csv"):
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT timestamp, indicator, vt_result, otx_result, verdict, score
        FROM history
        ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "timestamp",
            "indicator",
            "ioc_type",
            "vt_malicious",
            "vt_suspicious",
            "otx_pulses",
            "verdict",
            "score",
        ])
        writer.writeheader()

        for timestamp, indicator, vt_json, otx_json, verdict, score in rows:
            vt_data = json.loads(vt_json) if vt_json else {}
            otx_data = json.loads(otx_json) if otx_json else {}

            ioc_type = detect_type(indicator) or ""
            vt_malicious = vt_data.get("malicious", "")
            vt_suspicious = vt_data.get("suspicious", "")
            otx_pulses = otx_data.get("pulse_count", "")

            writer.writerow({
                "timestamp": timestamp,
                "indicator": indicator,
                "ioc_type": ioc_type,
                "vt_malicious": vt_malicious,
                "vt_suspicious": vt_suspicious,
                "otx_pulses": otx_pulses,
                "verdict": verdict,
                "score": score,
            })

    print(f"Exported history to {output_path}")


def get_history_entry(n):
    """Return the nth history entry (1-indexed, newest first), or None if out of range."""
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, indicator, vt_result, otx_result, abuse_result, shodan_result, verdict, whois_result
        FROM history
        ORDER BY id DESC
        LIMIT 1 OFFSET ?
    """, (n - 1,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    timestamp, indicator, vt_json, otx_json, abuse_json, shodan_json, verdict, whois_json = row
    return {
        "timestamp": timestamp,
        "indicator": indicator,
        "vt":        json.loads(vt_json) if vt_json else None,
        "otx":       json.loads(otx_json) if otx_json else None,
        "abuse":     json.loads(abuse_json) if abuse_json else None,
        "shodan":    json.loads(shodan_json) if shodan_json else None,
        "whois":     json.loads(whois_json) if whois_json else None,
        "verdict":   verdict,
    }
