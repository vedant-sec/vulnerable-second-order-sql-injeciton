"""
Second-Order SQL Injection Lab
-------------------------------
Recreates a real vulnerability class: a value (username) is stored safely
at signup, then later concatenated UNSAFELY into a SQL query by a
different feature (report generation). This is "second-order" SQLi —
the payload plants in one request and detonates in another.

Run: python3 app.py
Then browse to http://127.0.0.1:5000

VULNERABLE ON PURPOSE. Do not deploy publicly with real data.
"""

# Imports SQLite support for creating and querying the local database.
import sqlite3
# Imports operating-system helpers for filesystem and path operations.
import os
# Imports the Flask application class and request, response, routing, session, and context helpers.
from flask import Flask, request, render_template, redirect, url_for, session, g

# Creates the Flask application object for this module.
app = Flask(__name__)
# Sets the secret used by Flask to sign session cookies.
app.secret_key = "lab-only-not-for-production"
# Builds the path to the database file beside this Python module.
DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")


# ---------- DB helpers ----------

def get_db():
    # Reuses the database connection stored for the current request context when available.
    if "db" not in g:
        # Opens a SQLite connection to the lab database when no connection exists yet.
        g.db = sqlite3.connect(DB_PATH)
        # Makes query results behave like mappings keyed by column name.
        g.db.row_factory = sqlite3.Row
    # Returns the current request's database connection.
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    # Removes the connection from Flask's context storage, returning None when it is absent.
    db = g.pop("db", None)
    # Closes the connection if this request created one.
    if db is not None:
        # Releases the SQLite connection and its resources.
        db.close()


def init_db():
    # Checks whether an older lab database file already exists.
    if os.path.exists(DB_PATH):
        # Deletes the old database so initialization starts from a clean state.
        os.remove(DB_PATH)
    # Opens a connection used only while initializing the database.
    conn = sqlite3.connect(DB_PATH)
    # Creates a cursor for executing schema and seed statements.
    cur = conn.cursor()

    # NOTE: signup uses a parameterized INSERT -> this part is genuinely safe,
    # exactly like the picoCTF app. The bug is NOT here.
    # Executes the SQL statement that creates the users table.
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Executes the SQL statement that creates the expenses table.
    cur.execute("""
        CREATE TABLE expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            description TEXT NOT NULL,
            amount REAL NOT NULL,
            date TEXT NOT NULL
        )
    """)

    # A "secret" table an attacker should not normally reach -
    # stands in for the base64-named table in the real challenge.
    # Executes the SQL statement that creates the secret flag table.
    cur.execute("""
        CREATE TABLE flag_vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            secret TEXT NOT NULL
        )
    """)
    # Inserts the lab secret using a parameter placeholder.
    cur.execute("INSERT INTO flag_vault (secret) VALUES (?)",
                # Supplies the secret value for the placeholder.
                ("LAB{s3c0nd_0rd3r_sqli_via_username_field}",))

    # seed one normal user + some expenses so the app isn't empty
    # Inserts the demo user's credentials using parameter placeholders.
    cur.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                # Supplies the demo username and password values.
                ("demo", "demo123"))
    # Inserts the demo user's first expense using parameter placeholders.
    cur.execute("INSERT INTO expenses (username, description, amount, date) VALUES (?,?,?,?)",
                # Supplies the first demo expense values.
                ("demo", "coffee", 4.50, "2026-08-01"))
    # Inserts the demo user's second expense using parameter placeholders.
    cur.execute("INSERT INTO expenses (username, description, amount, date) VALUES (?,?,?,?)",
                # Supplies the second demo expense values.
                ("demo", "books", 39.99, "2026-08-10"))

    # Commits the schema and seed data to disk.
    conn.commit()
    # Closes the initialization connection.
    conn.close()


# ---------- Routes ----------

@app.route("/")
def index():
    # Sends authenticated users to expenses and everyone else to login.
    return redirect(url_for("expenses") if "username" in session else url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    # Starts with no signup error to pass to the template.
    error = None
    # Processes submitted signup data only for POST requests.
    if request.method == "POST":
        # Reads the submitted username, defaulting to an empty string.
        username = request.form.get("username", "")
        # Reads the submitted password, defaulting to an empty string.
        password = request.form.get("password", "")

        # Retrieves the request-scoped database connection.
        db = get_db()
        # SAFE: parameterized insert - mirrors the real app's signup form.
        # This is intentional: the bug is NOT at input time, it's at
        # query-build time later in generate_report(). Testing this field
        # here with a ' will show nothing interesting - that's the point.
        # Executes the parameterized user insertion.
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                   # Binds the submitted username and password to the placeholders.
                   (username, password))

        # Persists the newly created user.
        db.commit()
        # Stores the new username in the user's Flask session.
        session["username"] = username
        # Redirects the newly signed-up user to the expenses page.
        return redirect(url_for("expenses"))
    # Renders the signup form for GET requests or after processing.
    return render_template("signup.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    # Starts with no login error to pass to the template.
    error = None
    # Processes submitted credentials only for POST requests.
    if request.method == "POST":
        # Reads the submitted username.
        username = request.form.get("username", "")
        # Reads the submitted password.
        password = request.form.get("password", "")
        # Retrieves the request-scoped database connection.
        db = get_db()
        # Executes a parameterized lookup for matching credentials.
        row = db.execute(
            # Selects the complete user row whose username and password match.
            "SELECT * FROM users WHERE username = ? AND password = ?",
            # Binds the submitted credentials to the query placeholders.
            (username, password),
        # Fetches the first matching row, if one exists.
        ).fetchone()
        # Checks whether the credential lookup found a user.
        if row:
            # Stores the authenticated username in the session.
            session["username"] = username
            # Redirects an authenticated user to the expenses page.
            return redirect(url_for("expenses"))
        # Records the message shown when credentials do not match.
        error = "Invalid credentials"
    # Renders the login form and any login error.
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    # Removes all values from the current user's session.
    session.clear()
    # Redirects the logged-out user to the login page.
    return redirect(url_for("login"))


@app.route("/expenses", methods=["GET", "POST"])
def expenses():
    # Requires a username in the session before showing or changing expenses.
    if "username" not in session:
        # Redirects unauthenticated users to login.
        return redirect(url_for("login"))

    # Retrieves the request-scoped database connection.
    db = get_db()
    # Processes a submitted expense only for POST requests.
    if request.method == "POST":
        # Reads the submitted expense description.
        description = request.form.get("description", "")
        # Reads the submitted expense amount as text.
        amount = request.form.get("amount", "0")
        # Reads the submitted expense date.
        date = request.form.get("date", "")
        # Also parameterized - safe, same as the real app.
        # Executes the parameterized expense insertion.
        db.execute(
            # Inserts the session username and submitted expense fields.
            "INSERT INTO expenses (username, description, amount, date) VALUES (?, ?, ?, ?)",
            # Binds all four values to the insertion placeholders.
            (session["username"], description, amount, date),
        )
        # Persists the new expense.
        db.commit()

    # Queries all expenses belonging to the current session username.
    rows = db.execute(
        # Selects only the fields displayed by the expenses page.
        "SELECT description, amount, date FROM expenses WHERE username = ?",
        # Binds the current username safely to the query.
        (session["username"],),
    # Retrieves every matching expense row.
    ).fetchall()
    # Renders the expenses page with its rows and current username.
    return render_template("expenses.html", expenses=rows, username=session["username"])


@app.route("/generate_report")
def generate_report():
    """
    *** THE VULNERABLE ENDPOINT ***

    This mirrors the real bug: the stored `username` (set once, at signup,
    with no restriction on its characters) is pulled BACK OUT of the
    session/db and concatenated directly into a SQL string here -
    with no parameterization. Anything the attacker put in their
    username at signup now executes as SQL.
    """
    # Requires a logged-in username before generating a report.
    if "username" not in session:
        # Redirects unauthenticated users to login.
        return redirect(url_for("login"))

    # Reads the stored username from the current user's session.
    username = session["username"]
    # Retrieves the request-scoped database connection.
    db = get_db()

    # VULNERABLE: f-string concatenation of user-controlled data into SQL.
    # Builds the report query by interpolating the stored username into SQL.
    query = f"SELECT description, amount, date FROM expenses WHERE username = '{username}'"

    # Attempts to execute the generated report query.
    try:
        # Fetches all rows returned by the report query.
        rows = db.execute(query).fetchall()
        # Clears any prior error because the query succeeded.
        error = None
    # Handles SQLite errors raised while executing the report query.
    except sqlite3.Error as e:
        # Uses an empty result set when the query fails.
        rows = []
        # Converts the database error into text for the report template.
        error = str(e)

    # Renders the report page with result rows, error details, and context values.
    return render_template(
        # Selects the report template.
        "report.html",
        # Passes the query result rows to the template.
        rows=rows,
        # Passes any database error to the template.
        error=error,
        # Passes the generated query to the template for display.
        query=query,
        # Passes the stored username to the template.
        username=username,
    )


if __name__ == "__main__":
    # Recreates and seeds the database when this file is run directly.
    init_db()
    # Prints the location of the initialized database.
    print("Lab DB initialized at", DB_PATH)
    # Prints guidance to try a normal username first.
    print("Try signing up with a normal username first, use the app,")
    # Prints the second-order SQL injection demonstration prompt.
    print("then sign up again with a payload username like:")
    # Prints an example username payload that targets SQLite metadata.
    print("   ' UNION SELECT name,NULL,NULL FROM sqlite_master WHERE type='table'--")
    # Starts the Flask development server on the loopback interface and port 5000.
    app.run(host="127.0.0.1", port=5000, debug=True)
