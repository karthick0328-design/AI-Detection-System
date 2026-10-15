"""
Flask Web Application & API Server.

AI-Based Phishing Website Detection System — Explainable AI & Digital Safety Assistant.
"""

import os
import secrets
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any

from flask import (
    Flask, render_template, request, redirect,
    url_for, jsonify, flash, session, Response, abort
)

from config import Config
from src.feature_extraction import sanitize_and_normalize_url, extract_features
from src.prediction import analyze_url, get_model_artifacts
from src.database import (
    init_db, save_scan, get_scan, list_scans,
    delete_scan, clear_history, get_analytics_summary, export_scans_csv,
    get_db_connection
)

app = Flask(__name__)
app.config.from_object(Config)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

# Ensure required directories exist and initialize database
with app.app_context():
    init_db()

def generate_csrf_token() -> str:
    """Generates and stores a unique CSRF token in session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(24)
    return session["_csrf_token"]

@app.context_processor
def inject_csrf_token():
    """Makes csrf_token available in all Jinja templates."""
    return dict(csrf_token=generate_csrf_token())

def validate_csrf():
    """Validates submitted CSRF token against active session."""
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get("_csrf_token")
    if not expected or not token or not secrets.compare_digest(str(token), str(expected)):
        abort(403, description="CSRF verification failed. Request rejected.")


# --- Security Headers ---
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com data:;"
    )
    return response


# --- Web Page Routes ---
# --- Web Page Routes ---
@app.route("/")
def index():
    """Landing Page (Screen 1) with URL input, sample targets, system overview, and limitations."""
    samples = [
        {"title": "Search Engine", "url": "https://www.google.com", "badge": "Legitimate Sample"},
        {"title": "Open Source Hub", "url": "https://github.com", "badge": "Legitimate Sample"},
        {"title": "Account Verify Attack", "url": "http://192.168.1.1/paypal-account-verify-login.php", "badge": "Phishing Sample"},
        {"title": "Brand Impersonation", "url": "http://appleid-apple.com.login-auth-id.info/login.php", "badge": "Phishing Sample"}
    ]
    return render_template("index.html", samples=samples, is_landing=True)


@app.route("/scanner")
def scanner_view():
    """Dedicated URL Scanner interface (Screen 2) with recent scans and samples."""
    records, _ = list_scans(limit=5)
    samples = [
        {"url": "https://www.google.com", "name": "google.com"},
        {"url": "http://xmas-lottery-gift.top/claim.php", "name": "xmas-lot.com"},
        {"url": "https://bit.ly/secure-login", "name": "bit.ly/secure-login"},
        {"url": "https://microsoft.com", "name": "microsoft.com"}
    ]
    return render_template("scanner.html", recent_scans=records, samples=samples)


@app.route("/bulk-scanner")
def bulk_scanner_view():
    """Bulk URL Scanner interface (Screen 5) for CSV batch scanning."""
    return render_template("bulk_scanner.html")


@app.route("/bulk/template.csv")
def bulk_template_csv():
    """Generates a downloadable CSV sample template for bulk scanning."""
    csv_content = "url\nhttps://google.com\nhttps://bit.ly/secure-login\nhttp://appleid-verify.info\nhttps://github.com\n"
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishingguard_bulk_sample.csv"}
    )


@app.route("/api/bulk-scan", methods=["POST"])
def api_bulk_scan():
    """Batch analysis API for uploaded URLs."""
    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])
    if not urls:
        return jsonify({"success": False, "error": "No URLs provided"}), 400

    results = []
    for raw_url in urls[:50]:
        raw_url = raw_url.strip()
        if not raw_url:
            continue
        try:
            res = analyze_url(raw_url)
            results.append({
                "url": raw_url,
                "prediction": res["prediction"],
                "risk_category": res["risk_category"],
                "risk_score": res["risk_score"],
                "warning_count": res["warning_count"]
            })
        except Exception as exc:
            results.append({
                "url": raw_url,
                "prediction": "Evaluation Error",
                "risk_category": "Error",
                "risk_score": 0,
                "error": str(exc)
            })
    return jsonify({"success": True, "results": results})


@app.route("/qr-scanner")
def qr_scanner_view():
    """QR Code Scanner interface (Screen 6) to decode and verify QR links."""
    return render_template("qr_scanner.html")


@app.route("/email-analyzer", methods=["GET", "POST"])
def email_analyzer_view():
    """Email Phishing Analyzer interface (Screen 7)."""
    return render_template("email_analyzer.html")


@app.route("/api/email-analyze", methods=["POST"])
def api_email_analyze():
    """API endpoint to parse email body and headers for social engineering & phishing signals."""
    data = request.get_json(silent=True) or {}
    content = data.get("content", "")
    headers = data.get("headers", "")
    if not content and not headers:
        return jsonify({"success": False, "error": "Email content or headers required."}), 400

    from src.email_analyzer import analyze_email_text
    analysis = analyze_email_text(content, headers)
    return jsonify({"success": True, "result": analysis})


@app.route("/account")
def account_view():
    """User Account and PDF Reporting interface (Screen 8)."""
    return render_template("account.html")


@app.route("/education")
def education_view():
    """Security Education Centre and interactive quizzes (Screen 9)."""
    return render_template("education.html")


@app.route("/navigation")
def navigation_view():
    """Complete platform sitemap and navigation overview (Screen 12)."""
    return render_template("navigation.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """Validates, sanitizes, analyzes URL, stores scan record, and redirects to result."""
    validate_csrf()
    raw_url = request.form.get("url", "").strip()
    
    if not raw_url:
        flash("Please enter a website URL to analyze.", "warning")
        return redirect(url_for("index"))

    try:
        # Perform end-to-end inference and feature extraction
        result = analyze_url(raw_url)
    except ValueError as val_err:
        flash(f"Invalid URL: {str(val_err)}", "danger")
        return redirect(url_for("index"))
    except Exception as exc:
        flash(f"Analysis error: {str(exc)}", "danger")
        return redirect(url_for("index"))

    # Save to SQLite database
    try:
        dns_status = result["domain_checks"]["dns_resolution"]["status"]
        scan_id = save_scan(
            submitted_url=result["submitted_url"],
            normalized_url=result["normalized_url"],
            hostname=result["hostname"],
            prediction=result["prediction"],
            risk_category=result["risk_category"],
            risk_score=result["risk_score"],
            model_probability=result["model_probability"],
            warning_count=result["warning_count"],
            dns_status=dns_status,
            signals=result["all_signals"]
        )
    except Exception as db_err:
        print(f"[-] Database save error: {db_err}")
        scan_id = 0

    return redirect(url_for("result_view", scan_id=scan_id))


@app.route("/result/<int:scan_id>")
def result_view(scan_id: int):
    """Displays detailed analysis report for a specific scan (Screen 3)."""
    scan = get_scan(scan_id)
    if not scan:
        flash("Scan record not found.", "warning")
        return redirect(url_for("index"))

    # Check model metadata for display
    _, _, metadata = get_model_artifacts()
    model_meta = metadata or {
        "model_name": "Random Forest Classifier",
        "version": "1.0.0",
        "dataset_source": "Mitake/PhishingURLsANDBenignURLs"
    }

    return render_template("result.html", scan=scan, metadata=model_meta)


@app.route("/explain")
@app.route("/explain/<int:scan_id>")
def explain_view(scan_id: int = None):
    """Dedicated Explainable AI deep-dive page (Screen 4) detailing all signals and limitations."""
    scan = None
    if scan_id:
        scan = get_scan(scan_id)

    if not scan:
        records, _ = list_scans(limit=1)
        if records:
            scan = get_scan(records[0]["id"])

    if not scan:
        demo_url = "https://bit.ly/secure-login"
        try:
            res = analyze_url(demo_url)
            scan = {
                "id": 0,
                "submitted_url": demo_url,
                "normalized_url": res["normalized_url"],
                "hostname": res["hostname"],
                "prediction": res["prediction"],
                "risk_category": res["risk_category"],
                "risk_score": res["risk_score"],
                "model_probability": res["model_probability"],
                "warning_count": res["warning_count"],
                "dns_status": res["domain_checks"]["dns_resolution"]["status"],
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "signals": res["all_signals"]
            }
        except Exception:
            pass

    return render_template("explain.html", scan=scan)


@app.route("/history")
def history_view():
    """Scan history page with search, filters, pagination, and deletion."""
    search = request.args.get("q", "").strip()
    prediction_filter = request.args.get("prediction", "all")
    sort_by = request.args.get("sort", "date_desc")
    page = max(1, int(request.args.get("page", 1)))
    per_page = 15
    offset = (page - 1) * per_page

    records, total_count = list_scans(
        search=search,
        prediction=prediction_filter,
        sort_by=sort_by,
        limit=per_page,
        offset=offset
    )

    total_pages = max(1, (total_count + per_page - 1) // per_page)

    return render_template(
        "history.html",
        records=records,
        total_count=total_count,
        search=search,
        prediction_filter=prediction_filter,
        sort_by=sort_by,
        page=page,
        total_pages=total_pages
    )


@app.route("/analytics")
def analytics_view():
    """Database-driven security analytics dashboard."""
    summary = get_analytics_summary()
    return render_template("analytics.html", summary=summary)


@app.route("/about")
def about_view():
    """Methodology, dataset provenance, architecture, and academic project details."""
    eval_path = Path(Config.EVALUATION_PATH)
    eval_data = {}
    if eval_path.exists():
        try:
            with open(eval_path, "r", encoding="utf-8") as f:
                eval_data = json.load(f)
        except Exception:
            eval_data = {}

    return render_template("about.html", eval_data=eval_data)


# --- REST API Endpoints ---
@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """JSON API to evaluate a URL."""
    data = request.get_json(silent=True) or {}
    url = data.get("url") or request.form.get("url")
    if not url:
        return jsonify({"success": False, "error": "URL parameter is required."}), 400

    try:
        result = analyze_url(url)
        dns_status = result["domain_checks"]["dns_resolution"]["status"]
        scan_id = save_scan(
            submitted_url=result["submitted_url"],
            normalized_url=result["normalized_url"],
            hostname=result["hostname"],
            prediction=result["prediction"],
            risk_category=result["risk_category"],
            risk_score=result["risk_score"],
            model_probability=result["model_probability"],
            warning_count=result["warning_count"],
            dns_status=dns_status,
            signals=result["all_signals"]
        )
        result["scan_id"] = scan_id
        result["success"] = True
        return jsonify(result), 200
    except ValueError as val_err:
        return jsonify({"success": False, "error": str(val_err)}), 400
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/api/scan/<int:scan_id>")
def api_get_scan(scan_id: int):
    """Returns details for a single scan by ID."""
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"success": False, "error": "Scan not found."}), 404
    return jsonify({"success": True, "scan": scan}), 200


@app.route("/api/scan/<int:scan_id>/delete", methods=["POST"])
def api_delete_scan(scan_id: int):
    """Deletes an individual scan record with CSRF verification."""
    validate_csrf()
    deleted = delete_scan(scan_id)
    if not deleted:
        return jsonify({"success": False, "error": "Record not found or already deleted."}), 404
    
    if request.is_json:
        return jsonify({"success": True, "message": f"Scan #{scan_id} deleted."}), 200
    flash(f"Scan #{scan_id} deleted successfully.", "info")
    return redirect(url_for("history_view"))


@app.route("/api/history/clear", methods=["POST"])
def api_clear_history():
    """Clears all scan history with CSRF verification."""
    validate_csrf()
    count = clear_history()
    if request.is_json:
        return jsonify({"success": True, "deleted_count": count}), 200
    flash(f"Successfully cleared all {count} scan records.", "info")
    return redirect(url_for("history_view"))


@app.route("/api/analytics")
def api_analytics():
    """Returns real database-driven analytics in JSON."""
    return jsonify(get_analytics_summary()), 200


@app.route("/export/csv")
def export_csv():
    """Exports all scan records to CSV."""
    csv_data = export_scans_csv()
    filename = f"phishing_scans_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/health")
@app.route("/api/health")
def health_check():
    """System health check endpoint supporting both rich UI and JSON telemetry."""
    model, _, _ = get_model_artifacts()
    
    db_status = "sqlite_ready"
    total_scans = 0
    try:
        conn = get_db_connection()
        total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        conn.close()
    except Exception as e:
        db_status = f"error: {str(e)}"

    health_data = {
        "status": "healthy" if model is not None and "error" not in db_status else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model_loaded": model is not None,
        "database": db_status,
        "total_scans_stored": total_scans,
        "model_name": "Random Forest Classifier",
        "features_count": 18,
        "ssrf_protection": "active",
        "csrf_protection": "active"
    }

    # Deliver HTML for browsers requesting pages, JSON for API/tool callers
    accept_header = request.headers.get("Accept", "")
    is_browser = (
        "text/html" in accept_header
        and not request.is_json
        and request.args.get("format") != "json"
    )

    if is_browser:
        return render_template("health.html", health=health_data)

    return jsonify(health_data), 200


# --- Error Handlers ---
@app.errorhandler(403)
def forbidden_error(e):
    if request.is_json:
        return jsonify({"error": "Forbidden", "message": str(e)}), 403
    return render_template("base.html", error_title="403 Forbidden", error_msg=str(e)), 403

@app.errorhandler(404)
def not_found_error(e):
    if request.is_json:
        return jsonify({"error": "Not Found", "message": "The requested resource was not found."}), 404
    return render_template("base.html", error_title="404 Not Found", error_msg="The requested page does not exist."), 404

@app.errorhandler(500)
def internal_server_error(e):
    if request.is_json:
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred."}), 500
    return render_template("base.html", error_title="500 Internal Error", error_msg="An internal application error occurred."), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
