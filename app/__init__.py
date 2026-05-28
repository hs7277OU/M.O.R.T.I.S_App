from flask import Flask
from .models import db, User 

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY="change-this-in-production",
        SQLALCHEMY_DATABASE_URI="sqlite:///mortis.sqlite3",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    db.init_app(app)

    from .routes import bp
    app.register_blueprint(bp)

    with app.app_context():
        db.create_all()

        dmin_user = User.query.filter_by(username="admin").first()

        if not admin_user:
            admin_user = User(username="admin")
            admin_user.set_password("mortis123")
            db.session.add(admin_user)
            db.session.commit()
        elif not admin_user.check_password("mortis123"):
            admin_user.set_password("mortis123")
            db.session.commit()
    return app