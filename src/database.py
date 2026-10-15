"""
SQLite Database Layer for Scan History and Analytics.

Uses parameterized queries, explicit schema migrations, transaction safety,
and graceful error handling. Stores scan records, feature extractions,
and calculated risk assessments.
"""

import sqlite3
import json
import io
import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from config import Config

def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Creates a configured connection with row factory enabled."""
    path = db_path or Config.DATABASE_PATH
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for concurrent read/write performance
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initializes the database schema if tables do not exist."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    submitted_url TEXT NOT NULL,
                    normalized_url TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    risk_category TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    model_probability REAL,
                    warning_count INTEGER DEFAULT 0,
                    dns_status TEXT DEFAULT 'Not checked',
                    signals_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_prediction ON scans(prediction);
            """)
    finally:
        conn.close()


def save_scan(
    submitted_url: str,
    normalized_url: str,
    hostname: str,
    prediction: str,
    risk_category: str,
    risk_score: float,
    model_probability: Optional[float],
    warning_count: int,
    dns_status: str,
    signals: Dict[str, Any],
    db_path: Optional[str] = None
) -> int:
    """Saves an analysis record and returns the new scan ID."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("""
                INSERT INTO scans (
                    submitted_url, normalized_url, hostname, prediction,
                    risk_category, risk_score, model_probability,
                    warning_count, dns_status, signals_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                submitted_url,
                normalized_url,
                hostname,
                prediction,
                risk_category,
                float(risk_score),
                float(model_probability) if model_probability is not None else None,
                int(warning_count),
                dns_status,
                json.dumps(signals),
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            ))
            return cursor.lastrowid
    finally:
        conn.close()


def get_scan(scan_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves a single scan by ID."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("""
            SELECT * FROM scans WHERE id = ?
        """, (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        data = dict(row)
        if data.get("signals_json"):
            try:
                data["signals"] = json.loads(data["signals_json"])
            except Exception:
                data["signals"] = {}
        else:
            data["signals"] = {}
        return data
    finally:
        conn.close()


def list_scans(
    search: Optional[str] = None,
    prediction: Optional[str] = None,
    sort_by: str = "date_desc",
    limit: int = 50,
    offset: int = 0,
    db_path: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Lists scans with search, filter, and pagination.
    
    Returns:
        Tuple[List[Dict[str, Any]], int]: (records, total_count)
    """
    conn = get_db_connection(db_path)
    try:
        where_clauses = []
        params: List[Any] = []

        if search and search.strip():
            where_clauses.append("(submitted_url LIKE ? OR hostname LIKE ?)")
            pattern = f"%{search.strip()}%"
            params.extend([pattern, pattern])

        if prediction and prediction.strip() and prediction.lower() != "all":
            where_clauses.append("LOWER(prediction) = LOWER(?)")
            params.append(prediction.strip())

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        # Total count query
        count_cursor = conn.execute(f"SELECT COUNT(*) FROM scans {where_sql}", params)
        total_count = count_cursor.fetchone()[0]

        # Order by mapping
        order_map = {
            "date_desc": "created_at DESC",
            "date_asc": "created_at ASC",
            "risk_desc": "risk_score DESC",
            "risk_asc": "risk_score ASC"
        }
        order_sql = order_map.get(sort_by, "created_at DESC")

        query_sql = f"""
            SELECT id, submitted_url, normalized_url, hostname, prediction,
                   risk_category, risk_score, model_probability, warning_count,
                   dns_status, created_at
            FROM scans
            {where_sql}
            ORDER BY {order_sql}
            LIMIT ? OFFSET ?
        """
        records_cursor = conn.execute(query_sql, params + [limit, offset])
        records = [dict(r) for r in records_cursor.fetchall()]
        return records, total_count
    finally:
        conn.close()


def delete_scan(scan_id: int, db_path: Optional[str] = None) -> bool:
    """Deletes a single scan by ID."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()


def clear_history(db_path: Optional[str] = None) -> int:
    """Clears all scan history."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute("DELETE FROM scans")
            return cursor.rowcount
    finally:
        conn.close()


def get_analytics_summary(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Computes real database-driven analytics for the dashboard:
    - Total scans
    - Phishing, Legitimate, Uncertain counts
    - Average risk score
    - Recent scans trend (daily / chronological)
    - Most frequent warning signals
    """
    conn = get_db_connection(db_path)
    try:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        if total == 0:
            return {
                "total_scans": 0,
                "phishing_count": 0,
                "legitimate_count": 0,
                "uncertain_count": 0,
                "avg_risk_score": 0.0,
                "prediction_distribution": [],
                "scan_trend": [],
                "top_signals": []
            }

        phishing = conn.execute("SELECT COUNT(*) FROM scans WHERE LOWER(prediction) LIKE '%phishing%'").fetchone()[0]
        legitimate = conn.execute("SELECT COUNT(*) FROM scans WHERE LOWER(prediction) LIKE '%legitimate%'").fetchone()[0]
        uncertain = conn.execute("SELECT COUNT(*) FROM scans WHERE LOWER(prediction) LIKE '%uncertain%'").fetchone()[0]
        avg_score = conn.execute("SELECT AVG(risk_score) FROM scans").fetchone()[0] or 0.0

        # Scan trends by date
        trend_cursor = conn.execute("""
            SELECT DATE(created_at) as scan_date, COUNT(*) as count
            FROM scans
            GROUP BY DATE(created_at)
            ORDER BY scan_date ASC
            LIMIT 30
        """)
        scan_trend = [{"date": row["scan_date"], "count": row["count"]} for row in trend_cursor.fetchall()]

        # Compute signal frequencies from saved scans
        signal_counts: Dict[str, int] = {}
        rows_cursor = conn.execute("SELECT signals_json FROM scans WHERE signals_json IS NOT NULL ORDER BY id DESC LIMIT 500")
        for row in rows_cursor:
            try:
                sig_dict = json.loads(row["signals_json"])
                for sig_key, sig_data in sig_dict.items():
                    if sig_data.get("flagged"):
                        sig_name = sig_data.get("name", sig_key)
                        signal_counts[sig_name] = signal_counts.get(sig_name, 0) + 1
            except Exception:
                continue

        sorted_signals = sorted(signal_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        top_signals = [{"signal": k, "count": v} for k, v in sorted_signals]

        return {
            "total_scans": total,
            "phishing_count": phishing,
            "legitimate_count": legitimate,
            "uncertain_count": uncertain,
            "avg_risk_score": round(float(avg_score), 2),
            "prediction_distribution": [
                {"label": "Phishing", "count": phishing, "color": "#ef4444"},
                {"label": "Legitimate", "count": legitimate, "color": "#10b981"},
                {"label": "Uncertain", "count": uncertain, "color": "#f59e0b"}
            ],
            "scan_trend": scan_trend,
            "top_signals": top_signals
        }
    finally:
        conn.close()


def export_scans_csv(db_path: Optional[str] = None) -> str:
    """Exports all scan records to CSV string with safe escaping."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("""
            SELECT id, submitted_url, normalized_url, hostname, prediction,
                   risk_category, risk_score, model_probability, warning_count,
                   dns_status, created_at
            FROM scans
            ORDER BY created_at DESC
        """)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Scan ID", "Submitted URL", "Normalized URL", "Hostname",
            "Prediction", "Risk Category", "Risk Score (0-100)",
            "Model Probability", "Warning Count", "DNS Status", "Timestamp"
        ])
        for row in cursor.fetchall():
            writer.writerow([
                row["id"], row["submitted_url"], row["normalized_url"],
                row["hostname"], row["prediction"], row["risk_category"],
                row["risk_score"], row["model_probability"] or "",
                row["warning_count"], row["dns_status"], row["created_at"]
            ])
        return output.getvalue()
    finally:
        conn.close()
