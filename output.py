import sqlite3
import json
import datetime

from cache import DB_PATH
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
    try:
        conn.execute("ALTER TABLE history ADD COLUMN whois_result TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.close()

def save_results(indicator, vt_result, otx_result, abuse_result, shodan_result, verdict, whois_result=None):
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO history (timestamp, indicator, vt_result, otx_result, abuse_result, shodan_result, verdict, whois_result)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(indicator) DO UPDATE SET
            timestamp    = excluded.timestamp,
            vt_result    = excluded.vt_result,
            otx_result   = excluded.otx_result,
            abuse_result = excluded.abuse_result,
            shodan_result = excluded.shodan_result,
            verdict      = excluded.verdict,
            whois_result = excluded.whois_result
    """, (
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        indicator,
        json.dumps(vt_result),
        json.dumps(otx_result),
        json.dumps(abuse_result),
        json.dumps(shodan_result),
        verdict,
        json.dumps(whois_result),
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
        "vt":        json.loads(vt_json)    if vt_json    else None,
        "otx":       json.loads(otx_json)   if otx_json   else None,
        "abuse":     json.loads(abuse_json)  if abuse_json  else None,
        "shodan":    json.loads(shodan_json) if shodan_json else None,
        "whois":     json.loads(whois_json)  if whois_json  else None,
        "verdict":   verdict,
    }
