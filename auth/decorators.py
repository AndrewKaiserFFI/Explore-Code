from functools import wraps
from flask import abort
from flask_login import login_required, current_user

__all__ = ["login_required", "admin_required"]


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated
