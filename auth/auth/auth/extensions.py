# extensions.py
"""
Shared Flask extension instances, initialized here to avoid circular imports
between app.py, auth/routes.py, and other blueprints.
"""

from flask_bcrypt import Bcrypt
from flask_login import LoginManager

bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"