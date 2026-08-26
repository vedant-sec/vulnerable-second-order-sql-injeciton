# Second-Order SQL Injection Lab

A minimal Flask + SQLite app demonstrating **second-order SQL injection**:
user input is stored *safely* in one request, then read back and
concatenated *unsafely* into a query by a completely different feature.

Modeled after the picoCTF challenge "ORDER ORDER."

## Why this is interesting

Most SQLi testing checks the field you just submitted for an immediate
reflection or error. Second-order SQLi hides from that approach because
the payload doesn't fire where you type it — it fires later, somewhere
else in the app, once that stored value gets reused to build a new query.

In this lab:
- `POST /signup` stores `username` with a parameterized `INSERT` — genuinely safe.
- `GET /generate_report` later builds a query with an f-string:
  `f"SELECT ... WHERE username = '{username}'"` — genuinely vulnerable.

Testing `/signup` alone with `'` shows nothing. The bug only appears once
you generate a report with a malicious username already stored.

## Run it

Local:
```bash
pip install -r requirements.txt
python3 app.py          # vulnerable version, http://127.0.0.1:5000
python3 app_fixed.py     # patched version,   http://127.0.0.1:5001
```

Docker:
```bash
docker-compose up --build
# vulnerable: http://localhost:5000
# fixed:      http://localhost:5001
```

## Exploitation walkthrough

1. Sign up normally once (e.g. `demo1` / `pass`), add an expense, click
   **Generate Report** — confirms the baseline query works.

2. Log out. Sign up again with a payload as the **username**:
   ```
   ' ORDER BY 4--
   ```
   Log in as that user, click **Generate Report**. Compare `ORDER BY 3--`
   vs `ORDER BY 4--` — the point where it errors tells you the column
   count (3, matching `description, amount, date`).

3. Sign up again with a UNION payload to enumerate tables:
   ```
   ' UNION SELECT name,NULL,NULL FROM sqlite_master WHERE type='table'--
   ```
   Generate the report — the table names (including `flag_vault`) show
   up in the results table.

4. Sign up once more to dump the secret table:
   ```
   ' UNION SELECT secret,NULL,NULL FROM flag_vault--
   ```
   Generate the report — the flag is now in the output.

The report page also prints the exact SQL string that ran, so you can see
your payload land inside the query in real time.

## The fix (`app_fixed.py`)

One-line change: the username is passed as a bound parameter instead of
being spliced into the SQL string.

```python
# vulnerable
query = f"SELECT description, amount, date FROM expenses WHERE username = '{username}'"
db.execute(query)

# fixed
db.execute(
    "SELECT description, amount, date FROM expenses WHERE username = ?",
    (username,),
)
```

With the fix, the same payload usernames are just treated as literal
strings to match against — no rows match, no error, no injection.

## Takeaway

Any field that's *set once* (username, email, display name) and *read
again later by a different feature* (reports, exports, admin views,
emails) is a second-order injection candidate — even if the original
input point is fully parameterized. Test the read side, not just the
write side.

---
⚠️ Educational use only. Contains an intentional SQL injection
vulnerability — do not deploy publicly with real user data.
