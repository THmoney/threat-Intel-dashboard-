"""
Threat-intel feed aggregator.

Pulls PUBLIC, no-auth-required feeds from abuse.ch:
  - URLhaus: recently reported malicious URLs
  - Feodo Tracker: known malicious C2 IP addresses
  - ThreatFox: recent malware IOCs

Stores everything in a local SQLite FTS5 index for search_app.py.
"""

import csv
import os
import sqlite3
import time

import requests

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DB_PATH = os.path.join(DATA_DIR, "index.db")

URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
FEODO_CSV = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
THREATFOX_CSV = "https://threatfox.abuse.ch/export/csv/recent/"

REQUEST_TIMEOUT = 30
USER_AGENT = "Mozilla/5.0 (compatible; threat-intel-aggregator/0.1)"


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS indicators USING fts5(
            source, indicator, threat_type, tags, date_added, extra
        )
        """
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
    )
    conn.commit()
    return conn


def fetch_text(url):
    headers = {"User-Agent": USER_AGENT}
    resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
    resp.raise_for_status()
    return resp.text


def ingest_urlhaus(conn):
    print("[urlhaus] fetching recent malicious URLs...")
    raw = fetch_text(URLHAUS_CSV)
    lines = [line for line in raw.splitlines() if not line.startswith("#")]
    reader = csv.reader(lines)

    count = 0
    for row in reader:
        if len(row) < 9:
            continue
        _id, date_added, url, status, last_online, threat, tags, link, reporter = row[:9]
        conn.execute(
            """
            INSERT INTO indicators (source, indicator, threat_type, tags, date_added, extra)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("urlhaus", url, threat, tags, date_added, f"status={status} reporter={reporter}"),
        )
        count += 1

    conn.commit()
    print(f"[urlhaus] ingested {count} indicators")


def ingest_feodo(conn):
    print("[feodo] fetching malicious C2 IPs...")
    raw = fetch_text(FEODO_CSV)
    lines = [line for line in raw.splitlines() if not line.startswith("#")]
    reader = csv.reader(lines)

    count = 0
    for row in reader:
        if len(row) < 6:
            continue
        first_seen, dst_ip, dst_port, status, last_online, malware = row[:6]
        conn.execute(
            """
            INSERT INTO indicators (source, indicator, threat_type, tags, date_added, extra)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("feodotracker", dst_ip, malware, status, first_seen, f"port={dst_port}"),
        )
        count += 1

    conn.commit()
    print(f"[feodo] ingested {count} indicators")


def ingest_threatfox(conn):
    print("[threatfox] fetching recent IOCs...")
    raw = fetch_text(THREATFOX_CSV)
    lines = [line for line in raw.splitlines() if not line.startswith("#")]
    reader = csv.reader(lines, quotechar='"')

    count = 0
    for row in reader:
        if len(row) < 9:
            continue
        first_seen = row[0].strip('"')
        ioc_value = row[2].strip('"')
        ioc_type = row[3].strip('"')
        threat_type = row[4].strip('"')
        malware_printable = row[7].strip('"') if len(row) > 7 else ""

        conn.execute(
            """
            INSERT INTO indicators (source, indicator, threat_type, tags, date_added, extra)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("threatfox", ioc_value, malware_printable or threat_type, ioc_type, first_seen, threat_type),
        )
        count += 1

    conn.commit()
    print(f"[threatfox] ingested {count} indicators")


def clear_index(conn):
    conn.execute("DELETE FROM indicators")
    conn.commit()


def record_run_stats(conn):
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('last_ingest', ?)",
        (time.strftime("%Y-%m-%d %H:%M:%S UTC"),),
    )
    conn.commit()


def run():
    conn = init_db()
    clear_index(conn)

    try:
        ingest_urlhaus(conn)
    except requests.RequestException as e:
        print(f"[urlhaus] failed: {e}")

    try:
        ingest_feodo(conn)
    except requests.RequestException as e:
        print(f"[feodo] failed: {e}")

    try:
        ingest_threatfox(conn)
    except requests.RequestException as e:
        print(f"[threatfox] failed: {e}")

    record_run_stats(conn)

    total = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    print(f"\nDone. Index now has {total} indicators total.")
    conn.close()


if __name__ == "__main__":
    run()
