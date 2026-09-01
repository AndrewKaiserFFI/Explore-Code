import logging
from datetime import datetime

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from db import db_session
from models_auth import User, UserRole
from auth.forms import RegistrationForm, LoginForm
from extensions import bcrypt, login_manager

logger = logging.getLogger("auth")
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@login_manager.user_loader
def load_user(user_id):
    return db_session.query(User).get(int(user_id))


@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("reports.dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        password_hash = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user_count = db_session.query(User).count()
        role = UserRole.ADMIN if user_count == 0 else UserRole.VIEWER

        new_user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            password_hash=password_hash,
            role=role,
        )
        db_session.add(new_user)
        db_session.commit()

        logger.info(f"New user registered: {new_user.username} (role={role})")
        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/signup.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("reports.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = db_session.query(User).filter_by(username=form.username.data.strip()).first()

        if user is None or not bcrypt.check_password_hash(user.password_hash, form.password.data):
            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html", form=form)

        if not user.is_active_account:
            flash("This account has been disabled. Contact an administrator.", "danger")
            return render_template("auth/login.html", form=form)

        login_user(user)
        user.last_login_at = datetime.utcnow()
        db_session.commit()
        logger.info(f"User logged in: {user.username}")

        next_page = request.args.get("next")
        return redirect(next_page or url_for("reports.dashboard"))

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logger.info(f"User logged out: {current_user.username}")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
