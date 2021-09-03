from flask import redirect, render_template, request, session
from functools import wraps
import sqlite3


def setup_connection():
    connection = sqlite3.connect("schedge.db", isolation_level=None)
    connection.row_factory = sqlite3.Row 
    return connection.cursor()

def apology(message, code=400):
    """Render message as an apology to user."""

    c = setup_connection()
    c.execute("SELECT username FROM all_users WHERE id = ?", (session["user_id"], ))
    user_name = c.fetchall()

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message), user_name=user_name), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

