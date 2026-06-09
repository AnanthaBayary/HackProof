from flask import Flask, request, render_template, session, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets
import re
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_bank.db'
db = SQLAlchemy(app)
ph = PasswordHasher()

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']
app.jinja_env.globals['csrf_token'] = generate_csrf_token

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String(200))
    balance = db.Column(db.Float, default=1000.0)
    failed_logins = db.Column(db.Integer, default=0)

@app.route('/')
def index():
    return render_template('secure_index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            return "Username must be 3-20 alphanumeric characters"
        if len(password) < 8:
            return "Password must be at least 8 characters"
        password_hash = ph.hash(password)
        user = User(username=username, password_hash=password_hash)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('secure_register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            if user.failed_logins >= 5:
                return "Account locked due to too many failed attempts."
            try:
                ph.verify(user.password_hash, password)
                user.failed_logins = 0
                db.session.commit()
                session['user_id'] = user.id
                session['username'] = user.username
                return redirect(url_for('dashboard'))
            except VerifyMismatchError:
                user.failed_logins += 1
                db.session.commit()
                return "Invalid credentials"
        return "Invalid credentials"
    return render_template('secure_login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    from markupsafe import escape
    username = escape(session['username'])
    user = User.query.get(session['user_id'])
    return render_template('secure_dashboard.html', username=username, balance=user.balance)

@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    csrf_token_form = request.form.get('_csrf_token')
    if csrf_token_form != session.get('_csrf_token'):
        abort(403)
    to_account = request.form['to_account']
    amount = float(request.form['amount'])
    if amount <= 0 or amount > 10000:
        return "Invalid amount"
    recipient = User.query.filter_by(username=to_account).first()
    if not recipient:
        return "Recipient not found"
    sender = User.query.filter_by(username=session['username']).first()
    if sender.balance < amount:
        return "Insufficient funds"
    sender.balance -= amount
    recipient.balance += amount
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False, host='0.0.0.0', port=5001)
EOF