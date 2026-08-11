import secrets
from flask import Flask, request, render_template, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)
# NOTE: hardcoded for local teaching convenience only. In a real app this must be a
# long random value loaded from an environment variable / secret manager, never committed.
app.secret_key = "learn_cybersecurity_2024"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(120))
    balance = db.Column(db.Float, default=1000.0)


def get_mode():
    return request.args.get('mode', 'vulnerable')


def render_hacked(title, explanation, why, fix, payload=None, retry_mode_url='/'):
    """Stash the hack details and redirect to a dedicated GET page, so a
    page refresh doesn't resubmit the exploit."""
    session['last_hack'] = {
        'title': title, 'explanation': explanation, 'why': why,
        'fix': fix, 'payload': payload, 'retry_url': retry_mode_url,
    }
    return redirect(url_for('hacked'))


# ========== ROUTES ==========

@app.route('/')
def index():
    mode = get_mode()
    return render_template('index.html', mode=mode)


@app.route('/register', methods=['GET', 'POST'])
def register():
    mode = get_mode()

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not username or not password:
            return render_template('register.html', mode=mode, error="Username and password are required.")

        existing = User.query.filter_by(username=username).first()
        if existing:
            return render_template('register.html', mode=mode, error="Username already exists. Try another one.")

        # Password stored in plaintext on purpose for this teaching app — see the
        # note on the homepage. Never do this in production; hash with bcrypt/argon2.
        user = User(username=username, password=password, balance=1000)
        db.session.add(user)
        db.session.commit()

        flash('Account created — log in below.', 'success')
        return redirect(url_for('login', mode=mode))

    return render_template('register.html', mode=mode)


@app.route('/login', methods=['GET', 'POST'])
def login():
    mode = get_mode()

    if request.method == 'POST':
        username = request.form.get('username') or ''
        password = request.form.get('password') or ''
        mode = request.form.get('mode', 'vulnerable')

        if mode == 'vulnerable':
            # VULNERABLE: raw string interpolation into SQL.
            sql = text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")
            try:
                result = db.session.execute(sql).first()
            except Exception:
                result = None
        else:
            # SECURE: parameterized query, input is always treated as data.
            result = User.query.filter_by(username=username, password=password).first()

        if result:
            session['user_id'] = result.id
            session['username'] = result.username
            session['csrf_token'] = secrets.token_hex(16)

            looks_like_injection = "'" in username or "'" in password
            correct_password_matches = False
            real_user = User.query.filter_by(username=result.username).first()
            if real_user and real_user.password == password:
                correct_password_matches = True

            if mode == 'vulnerable' and looks_like_injection and not correct_password_matches:
                return render_hacked(
                    title="SQL Injection — authentication bypass",
                    explanation=f"You logged in as \"{result.username}\" without ever supplying a correct password.",
                    why="Your input was concatenated directly into the SQL query string. The quote character closed "
                        "out the password comparison early, and the OR condition you added is always true — so the "
                        "database happily returned a matching row.",
                    fix="Use parameterized queries (e.g. User.query.filter_by(...)) so user input is always bound as "
                        "data and can never change the shape of the query.",
                    payload=password,
                    retry_mode_url=url_for('login', mode='secure'),
                )

            return redirect(url_for('dashboard', mode=mode))
        else:
            return render_template('login.html', mode=mode, error="Invalid credentials!")

    return render_template('login.html', mode=mode)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login', mode=get_mode()))

    mode = get_mode()
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        flash('Your account no longer exists. Please log in again.', 'warning')
        return redirect(url_for('login', mode=mode))

    return render_template('dashboard.html', username=user.username, balance=user.balance, mode=mode)


@app.route('/transfer', methods=['POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login', mode=get_mode()))

    mode = get_mode()
    to_account = (request.form.get('to_account') or '').strip()
    raw_amount = request.form.get('amount')
    from_user = session['username']

    if not to_account or raw_amount is None:
        flash('Recipient and amount are both required.', 'warning')
        return redirect(url_for('dashboard', mode=mode))

    try:
        amount = float(raw_amount)
    except ValueError:
        flash('Amount must be a number.', 'warning')
        return redirect(url_for('dashboard', mode=mode))

    sender = User.query.filter_by(username=from_user).first()
    recipient = User.query.filter_by(username=to_account).first()

    if not recipient or not sender:
        flash('Recipient not found.', 'warning')
        return redirect(url_for('dashboard', mode=mode))

    if mode == 'vulnerable':
        # VULNERABLE: no amount validation, no CSRF check.
        is_csrf = 'csrf-demo' in (request.referrer or '')
        sender.balance -= amount
        recipient.balance += amount
        db.session.commit()

        if amount < 0:
            return render_hacked(
                title="Negative-amount transfer — business logic flaw",
                explanation=f"You sent -{abs(amount):.2f} to {to_account}, which increased your own balance instead "
                            f"of decreasing it.",
                why="The transfer code does \"sender.balance -= amount\" with no check that amount is positive. "
                    "Subtracting a negative number is the same as adding a positive one.",
                fix="Reject any amount that isn't strictly between 0 and a sane maximum, before touching the database.",
                payload=f"amount={amount}",
                retry_mode_url=url_for('dashboard', mode='secure'),
            )
        if is_csrf:
            return render_hacked(
                title="CSRF — forged transfer request",
                explanation=f"A page pretending to be an external site just moved {amount:.2f} out of your account "
                            f"to \"{to_account}\", without you filling out the real transfer form.",
                why="The /transfer endpoint only checks that a valid session cookie is attached — it doesn't check "
                    "where the request came from or whether you meant to send it. Your browser attaches cookies to "
                    "every request automatically, including ones triggered by a hidden form on another page.",
                fix="Require a random per-session CSRF token on every state-changing form, and reject requests "
                    "that don't include the correct one.",
                retry_mode_url=url_for('csrf_demo', mode='secure'),
            )
    else:
        # SECURE: validate amount, sufficient balance, and CSRF token.
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            flash('Transfer blocked: missing or invalid CSRF token.', 'success')
            return redirect(url_for('dashboard', mode=mode))
        if amount <= 0 or amount > 10000:
            flash('Invalid amount — must be between 1 and 10,000.', 'warning')
            return redirect(url_for('dashboard', mode=mode))
        if sender.balance < amount:
            flash('Insufficient funds.', 'warning')
            return redirect(url_for('dashboard', mode=mode))

        sender.balance -= amount
        recipient.balance += amount
        db.session.commit()
        flash(f'Transferred ${amount:.2f} to {to_account}.', 'success')

    return redirect(url_for('dashboard', mode=mode))


@app.route('/profile/<username>')
def profile(username):
    if 'user_id' not in session:
        return redirect(url_for('login', mode=get_mode()))

    mode = get_mode()
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found.', 'warning')
        return redirect(url_for('dashboard', mode=mode))

    if mode == 'vulnerable':
        if username != session['username']:
            return render_hacked(
                title="IDOR — accessed another user's profile",
                explanation=f"You viewed {username}'s profile (balance: ${user.balance:.2f}) just by changing the "
                            f"URL, while logged in as {session['username']}.",
                why="The /profile/<username> route trusts whatever username is in the URL and never checks it "
                    "against who's actually logged in.",
                fix="Compare the requested username against session['username'] (or, better, use an internal "
                    "user ID with a proper ownership/role check) before returning any data.",
                payload=f"/profile/{username}",
                retry_mode_url=url_for('profile', username=username, mode='secure'),
            )
    else:
        if username != session['username']:
            flash('Access denied — you can only view your own profile.', 'warning')
            return redirect(url_for('dashboard', mode=mode))

    return render_template('profile.html', user=user, mode=mode)


@app.route('/search')
def search():
    mode = get_mode()
    query = request.args.get('q', '')
    return render_template('search.html', query=query, mode=mode)


@app.route('/csrf-demo')
def csrf_demo():
    mode = get_mode()
    return render_template('csrf_demo.html', mode=mode)


@app.route('/hacked')
def hacked():
    data = session.pop('last_hack', None)
    if not data:
        flash("Nothing to show yet — go find a vulnerability first!", 'success')
        return redirect(url_for('index'))
    return render_template('hacked.html', **data)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.errorhandler(404)
def not_found(e):
    return render_template('index.html', mode=get_mode()), 404


# ========== CREATE DATABASE ==========

def seed_users():
    seed = [('admin', 'admin123', 999999), ('alice', 'alice123', 5000), ('bob', 'bob123', 3000)]
    for username, password, balance in seed:
        if not User.query.filter_by(username=username).first():
            db.session.add(User(username=username, password=password, balance=balance))
    db.session.commit()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_users()

    # debug=True + host 0.0.0.0 exposes Werkzeug's interactive debugger (arbitrary code
    # execution) to your whole network. Keep this on 127.0.0.1, or in an isolated VM/container.
    app.run(debug=True, host='127.0.0.1', port=5000)
