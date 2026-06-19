import sqlite3
import json
import datetime
import os

DB_PATH = "ioc_cache.db"

def cache_history():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ioc, source, result, cached_at
        FROM cache
        ORDER BY cached_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            ioc         TEXT NOT NULL,
            source      TEXT NOT NULL,
            result      TEXT NOT NULL,
            cached_at   TEXT NOT NULL,
            PRIMARY KEY (ioc, source)
        )
    """)
    conn.commit()
    conn.close()

def cache_get(ioc, source):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT result, cached_at FROM cache WHERE ioc = ? AND source = ?",
        (ioc, source)
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    cached_at = datetime.datetime.fromisoformat(row[1])
    age_days  = (datetime.datetime.now() - cached_at).days
    print(f"  [CACHE HIT] {source} — cached {age_days} day(s) ago")
    return json.loads(row[0])

def clear_cache():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM cache")
    conn.commit()
    conn.close()

def clear_indicator_cache(ioc):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cache WHERE ioc = ?", (ioc,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted

def cache_set(ioc, source, result):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO cache (ioc, source, result, cached_at)
        VALUES (?, ?, ?, ?)
    """, (
        ioc,
        source,
        json.dumps(result),
        datetime.datetime.now().isoformat()
    ))
    conn.commit()
    conn.close()
    print(f"  [CACHE SET] {source} result saved for {ioc}")