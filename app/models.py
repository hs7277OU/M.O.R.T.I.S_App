from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    overall_score = db.Column(db.Integer, default=0)
    overall_rating = db.Column(db.String(20), default="Low")
    report_summary = db.Column(db.Text, default="")

    # Progress fields updated by the background scan thread and polled by the UI.
    status = db.Column(db.String(20), default="running")  # running | completed | failed
    modules_total = db.Column(db.Integer, default=0)
    modules_done = db.Column(db.Integer, default=0)
    current_module = db.Column(db.String(80), default="")

    findings = db.relationship(
        "Finding",
        backref="scan",
        cascade="all, delete-orphan",
        lazy=True,
        order_by="Finding.score.desc()"
    )


class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False)

    module = db.Column(db.String(80), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    score = db.Column(db.Integer, default=0)

    # Optional CVSS v3.1 base score; null for findings with no vector.
    cvss_vector = db.Column(db.String(60), nullable=True)
    cvss_score = db.Column(db.Float, nullable=True)
    cvss_rating = db.Column(db.String(20), nullable=True)

    description = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)