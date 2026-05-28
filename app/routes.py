from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, send_file
from .models import db, User, Scan, Finding
from .scanner.engine import run_scan
from .reporting import generate_report
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
        flash("Invalid login. Default MVP login is admin / mortis123.", "error")
    return render_template("login.html")

@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))

@bp.route("/dashboard")
@login_required
def dashboard():
    scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    return render_template("dashboard.html", scans=scans)

@bp.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    if request.method == "POST":
        target_url = request.form.get("target_url", "")
        authorised = request.form.get("authorised") == "on"
        if not authorised:
            flash("You must confirm that you are authorised to test this target.", "error")
            return redirect(url_for("main.scan"))
        try:
            result = run_scan(target_url)
        except Exception as exc:
            flash(str(exc), "error")
            return redirect(url_for("main.scan"))
        report_summary = generate_report(result["target_url"], result["findings"], result["overall_rating"])
        scan_record = Scan(
            target_url=result["target_url"],
            overall_score=result["overall_score"],
            overall_rating=result["overall_rating"],
            report_summary=report_summary,
        )
        db.session.add(scan_record)
        db.session.flush()
        for f in result["findings"]:
            db.session.add(Finding(scan_id=scan_record.id, **f))
        db.session.commit()
        return redirect(url_for("main.results", scan_id=scan_record.id))
    return render_template("scan.html")

@bp.route("/results/<int:scan_id>")
@login_required
def results(scan_id):
    scan_record = Scan.query.get_or_404(scan_id)
    return render_template("results.html", scan=scan_record)

@bp.route("/report/<int:scan_id>.txt")
@login_required
def download_report(scan_id):
    scan_record = Scan.query.get_or_404(scan_id)
    lines = [
        "MORTIS MVP Scan Report",
        "======================",
        f"Target: {scan_record.target_url}",
        f"Overall rating: {scan_record.overall_rating}",
        "",
        scan_record.report_summary,
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
            "",
        ])
    data = "\n".join(lines).encode("utf-8")
    return send_file(io.BytesIO(data), as_attachment=True, download_name=f"mortis_report_{scan_id}.txt", 
mimetype="text/plain")