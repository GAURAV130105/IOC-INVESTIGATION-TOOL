import sqlite3
import json
import datetime

from cache import DB_PATH

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
        print(f"  {i}. {indicator:<20} {verdict:<20} {timestamp}")

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
            verdict     TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_results(indicator, vt_result, otx_result, verdict):
    init_history_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO history (timestamp, indicator, vt_result, otx_result, verdict)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(indicator) DO UPDATE SET
            timestamp  = excluded.timestamp,
            vt_result  = excluded.vt_result,
            otx_result = excluded.otx_result,
            verdict    = excluded.verdict
    """, (
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        indicator,
        json.dumps(vt_result),
        json.dumps(otx_result),
        verdict
    ))
    conn.commit()

    total = cursor.execute("SELECT COUNT(*) FROM history").fetchone()[0]
    conn.close()

    print(f"  Result saved to database ({total} total)")
