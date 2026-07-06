from datetime import datetime
from functools import wraps
from threading import Thread
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, send_file, jsonify, current_app
from .models import db, User, Scan, Finding
from .scanner.engine import run_scan
from .scanner.utils import normalise_url
from .reporting import generate_report_with_source, _strip_markdown
import io

bp = Blueprint("main", __name__)

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("main.login"))
        return view(*args, **kwargs)
    return wrapped

@bp.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("main.login"))

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("main.dashboard"))
        flash("Invalid login. Default Prototype login is admin / mortis123.", "error")
    return render_template("login.html")

@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))

@bp.route("/accessibility")
def accessibility():
    return render_template("accessibility.html")

@bp.route("/dashboard")
@login_required
def dashboard():
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    return render_template("dashboard.html", scans=scans)

def _execute_scan(app, scan_id, target_url, enabled_modules, depth):
    """Run the scan in a background thread, updating the Scan row's progress
    fields as each module completes so the progress page can poll for status.
    """
    with app.app_context():
        def on_progress(module_name, done, total):
            scan_record = db.session.get(Scan, scan_id)
            scan_record.modules_done = done
            scan_record.modules_total = total
            scan_record.current_module = module_name or ""
            db.session.commit()

        try:
            result = run_scan(target_url, enabled_modules=enabled_modules, depth=depth, on_progress=on_progress)

            # Modules are done; the summary (possibly a slow API call) is next.
            # Flag this phase so the progress page can show "generating report".
            scan_record = db.session.get(Scan, scan_id)
            scan_record.status = "reporting"
            db.session.commit()

            report_summary, report_source = generate_report_with_source(
                result["target_url"], result["findings"], result["overall_rating"])

            scan_record = db.session.get(Scan, scan_id)
            scan_record.overall_score = result["overall_score"]
            scan_record.overall_rating = result["overall_rating"]
            scan_record.report_summary = report_summary
            scan_record.report_source = report_source
            scan_record.status = "completed"
            for f in result["findings"]:
                db.session.add(Finding(scan_id=scan_record.id, **f))
            db.session.commit()
        except Exception as exc:
            scan_record = db.session.get(Scan, scan_id)
            scan_record.status = "failed"
            scan_record.report_summary = str(exc)
            db.session.commit()

@bp.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    if request.method == "POST":
        target_url = request.form.get("target_url", "")
        authorised = request.form.get("authorised") == "on"
        selected_modules = request.form.getlist("modules")
        depth = request.form.get("depth", "standard")
        if not authorised:
            flash("You must confirm that you are authorised to test this target.", "error")
            return redirect(url_for("main.scan"))
        if not selected_modules:
            flash("You must select at least one scan module to run a scan.", "error")
            return redirect(url_for("main.scan"))
        try:
            target_url = normalise_url(target_url)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("main.scan"))

        scan_record = Scan(target_url=target_url, status="running", modules_done=0, modules_total=0)
        db.session.add(scan_record)
        db.session.commit()

        app = current_app._get_current_object()
        Thread(target=_execute_scan, args=(app, scan_record.id, target_url, selected_modules, depth), daemon=True).start()

        return redirect(url_for("main.scan_progress", scan_id=scan_record.id))
    return render_template("scan.html")

@bp.route("/scan/<int:scan_id>/progress")
@login_required
def scan_progress(scan_id):
    scan_record = Scan.query.get_or_404(scan_id)
    if scan_record.status not in ("running", "reporting"):
        return redirect(url_for("main.results", scan_id=scan_id))
    return render_template("scan_progress.html", scan=scan_record)

@bp.route("/scan/<int:scan_id>/status")
@login_required
def scan_status(scan_id):
    scan_record = Scan.query.get_or_404(scan_id)
    return jsonify({
        "status": scan_record.status,
        "modules_done": scan_record.modules_done,
        "modules_total": scan_record.modules_total,
        "current_module": scan_record.current_module,
        "results_url": url_for("main.results", scan_id=scan_record.id),
    })

@bp.route("/results/<int:scan_id>")
@login_required
def results(scan_id):
    scan_record = Scan.query.get_or_404(scan_id)
    if scan_record.status in ("running", "reporting"):
        return redirect(url_for("main.scan_progress", scan_id=scan_id))
    return render_template("results.html", scan=scan_record)

@bp.route("/report/<int:scan_id>.txt")
@login_required
def download_report(scan_id):
    scan_record = Scan.query.get_or_404(scan_id)
    lines = [
        "MORTIS Prototype Scan Report",
        "=============================",
        f"Target: {scan_record.target_url}",
        f"Overall rating: {scan_record.overall_rating}",
        "",
        _strip_markdown(scan_record.report_summary or ""),
        "",
        "Findings",
        "--------",
    ]
    for f in scan_record.findings:
        lines.extend([
            f"{f.title} [{f.severity}]",
            f"Module: {f.module}",
            f"Description: {f.description}",
            f"Recommendation: {f.recommendation}",
        ])
        if f.cvss_score is not None:
            lines.append(f"CVSS v3.1: {f.cvss_score} ({f.cvss_rating}) - {f.cvss_vector}")
        lines.append("")
    data = "\n".join(lines).encode("utf-8")
    return send_file(io.BytesIO(data), as_attachment=True, download_name=f"mortis_report_{scan_id}.txt", mimetype="text/plain")

@bp.route("/report/<int:scan_id>.html")
@login_required
def download_report_html(scan_id):
    scan_record = Scan.query.get_or_404(scan_id)
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    counts = {s: 0 for s in severity_order}
    for f in scan_record.findings:
        if f.severity in counts:
            counts[f.severity] += 1
    html = render_template(
        "report.html",
        scan=scan_record,
        counts=counts,
        severity_order=severity_order,
        generated_at=datetime.utcnow(),
    )
    return send_file(io.BytesIO(html.encode("utf-8")), as_attachment=True,
                     download_name=f"mortis_report_{scan_id}.html", mimetype="text/html")
