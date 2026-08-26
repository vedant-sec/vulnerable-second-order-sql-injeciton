"""
Same lab, with generate_report() fixed using parameterized queries.
Diff against app.py to see the entire fix is a one-line change.

Run: python3 app_fixed.py
"""

import sqlite3
import os
from flask import Flask, request, render_template, redirect, url_for, session, g

app = Flask(__name__)
app.secret_key = "lab-only-not-for-production"
DB_PATH = os.path.join(os.path.dirname(__file__), "lab_fixed.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, password TEXT NOT NULL)""")
    cur.execute("""CREATE TABLE expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
        description TEXT NOT NULL, amount REAL NOT NULL, date TEXT NOT NULL)""")
    cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("demo", "demo123"))
    cur.execute("INSERT INTO expenses (username, description, amount, date) VALUES (?,?,?,?)",
                ("demo", "coffee", 4.50, "2026-08-01"))
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return redirect(url_for("expenses") if "username" in session else url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        db.commit()
        session["username"] = username
        return redirect(url_for("expenses"))
    return render_template("signup.html", error=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                          (username, password)).fetchone()
        if row:
            session["username"] = username
            return redirect(url_for("expenses"))
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/expenses", methods=["GET", "POST"])
def expenses():
    if "username" not in session:
        return redirect(url_for("login"))
    db = get_db()
    if request.method == "POST":
        db.execute(
            "INSERT INTO expenses (username, description, amount, date) VALUES (?, ?, ?, ?)",
            (session["username"], request.form.get("description", ""),
             request.form.get("amount", "0"), request.form.get("date", "")),
        )
        db.commit()
    rows = db.execute("SELECT description, amount, date FROM expenses WHERE username = ?",
                       (session["username"],)).fetchall()
    return render_template("expenses.html", expenses=rows, username=session["username"])


@app.route("/generate_report")
def generate_report():
    """
    *** THE FIX ***
    Only change from app.py: the username is passed as a bound
    parameter (the `?` placeholder) instead of being spliced into
    the SQL string. The driver sends it to SQLite as pure data,
    never as part of the query structure - so quotes, UNION,
    ORDER BY etc. in the username are just literal text to match
    against, not executable SQL.
    """
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    db = get_db()

    query_shown = "SELECT description, amount, date FROM expenses WHERE username = ?  -- param: " + username

    try:
        rows = db.execute(
            "SELECT description, amount, date FROM expenses WHERE username = ?",
            (username,),
        ).fetchall()
        error = None
    except sqlite3.Error as e:
        rows = []
        error = str(e)

    return render_template("report.html", rows=rows, error=error, query=query_shown, username=username)


if __name__ == "__main__":
    init_db()
    print("Fixed lab DB initialized at", DB_PATH)
    print("Same payloads that worked against app.py should now just be treated as literal text.")
    app.run(host="127.0.0.1", port=5001, debug=True)
