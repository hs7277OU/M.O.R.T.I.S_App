import os
import secrets

from dotenv import load_dotenv
from flask import Flask
from flask_wtf import CSRFProtect
from sqlalchemy import inspect, text

from .models import db, User

# Load variables from a local .env file (e.g. ANTHROPIC_API_KEY) if present.
load_dotenv()

csrf = CSRFProtect()


def _ensure_scan_columns():
    """Add columns introduced after a database was first created, so existing
    mortis.sqlite3 files keep working without being deleted.
    """
    existing = {col["name"] for col in inspect(db.engine).get_columns("scan")}
    if "report_source" not in existing:
        db.session.execute(text("ALTER TABLE scan ADD COLUMN report_source VARCHAR(20) DEFAULT ''"))
        db.session.commit()


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(16)),
        SQLALCHEMY_DATABASE_URI="sqlite:///mortis.sqlite3",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    db.init_app(app)
    csrf.init_app(app)

    from .routes import bp
    app.register_blueprint(bp)

    with app.app_context():
        db.create_all()
        _ensure_scan_columns()
        if not User.query.filter_by(username="admin").first():
            admin_password = os.environ.get("MORTIS_ADMIN_PW", "mortis123")
            user = User(username="admin")
            user.set_password(admin_password)
            db.session.add(user)
            db.session.commit()
    return app
