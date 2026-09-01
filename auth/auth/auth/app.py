# app.py
"""
Application factory / entry point.
Wires together extensions, auth blueprint, and (elsewhere) the reports
blueprint that exposes drift comparisons, remediation plans, breaking
changes, and remediation history — all gated behind login_required.
"""

import os
from flask import Flask

from extensions import bcrypt, login_manager
from db import init_db, db_session
from auth.routes import auth_bp
# from reports.routes import reports_bp  # drift reports / remediation views (separate module)


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-.env")
    app.config["WTF_CSRF_ENABLED"] = True

    bcrypt.init_app(app)
    login_manager.init_app(app)

    init_db()

    app.register_blueprint(auth_bp)
    # app.register_blueprint(reports_bp)

    @app.teardown_appcontext
    def remove_session(exception=None):
        db_session.remove()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)