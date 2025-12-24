import sqlite3
import json
from datetime import datetime

DATABASE_NAME = 'recon_scans.db'

def init_db():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            target TEXT NOT NULL,
            date_started TEXT NOT NULL,
            status TEXT NOT NULL,
            raw_results JSON,
            impact_summary TEXT,
            UNIQUE(target, date_started)
        )
    ''')
    conn.commit()
    conn.close()

def insert_scan(target):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    date_started = datetime.now().isoformat()
    cursor.execute(
        "INSERT INTO scans (target, date_started, status, raw_results) VALUES (?, ?, 'Pending', '{}')",
        (target, date_started)
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id

def update_scan_results(scan_id, results, impact_summary):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET status = 'Completed', raw_results = ?, impact_summary = ? WHERE id = ?",
        (json.dumps(results), impact_summary, scan_id)
    )
    conn.commit()
    conn.close()

def get_scan_by_id(scan_id):
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return row

init_db()
