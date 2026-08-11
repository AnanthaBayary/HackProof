# HackProof

A small Flask app for learning four common web vulnerabilities hands-on:
SQL Injection, XSS, IDOR, and CSRF. Every page has a Vulnerable/Secure mode
toggle so you can attack it, then immediately see the fix.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000**.

The database (`bank.db`, SQLite) and three test users are created
automatically on first run:

| username | password  |
|----------|-----------|
| admin    | admin123  |
| alice    | alice123  |
| bob      | bob123    |

## ⚠️ Run this locally only

- `debug=True` is left on because the "learn from the code" panels benefit
  from auto-reload, but Werkzeug's debugger allows arbitrary code execution
  if it's ever reachable from outside your machine. The app binds to
  `127.0.0.1` by default — **don't change that to `0.0.0.0` or deploy this
  publicly.**
- Passwords are stored in plaintext on purpose, so the SQL injection demo
  stays easy to read in a debugger/DB browser. Never do this in a real app.
- This is a teaching sandbox, not a hardened reference implementation —
  treat the "Secure Mode" code as "better," not "production-ready."

## What each vulnerability demo does

- **SQL Injection** (`/login`) — vulnerable mode builds the login query with
  an f-string; enter `' OR '1'='1' --` as the password to log in as `admin`
  without knowing it.
- **XSS** (`/register`, `/search`) — vulnerable mode marks output `| safe`,
  skipping Jinja2's default escaping. Try
  `<script>hackedBanner('XSS')</script>` as a username or search term.
- **IDOR** (`/profile/<username>`) — vulnerable mode never checks that the
  username in the URL matches who's logged in. Try `/profile/admin`.
- **CSRF** (`/csrf-demo`) — simulates an external page auto-submitting a
  transfer using your logged-in session cookie, with no CSRF token attached.

Whenever an attack actually succeeds, you're taken to a `/hacked` results
page explaining what happened, why it worked, and how the fix closes it —
then you can flip to Secure Mode and watch the same payload fail.
