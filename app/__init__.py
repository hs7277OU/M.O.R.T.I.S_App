import os
import secrets

from flask import Flask
from flask_wtf import CSRFProtect

from .models import db, User

csrf = CSRFProtect()


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
        if not User.query.filter_by(username="admin").first():
            admin_password = os.environ.get("MORTIS_ADMIN_PW", "mortis123")
            user = User(username="admin")
            user.set_password(admin_password)
            db.session.add(user)
            db.session.commit()
    return app
