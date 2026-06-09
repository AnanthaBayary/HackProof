
from flask import Flask, request, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = "hardcoded_secret_123"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(120))
    balance = db.Column(db.Float, default=1000.0)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user = db.Column(db.String(80))
    to_user = db.Column(db.String(80))
    amount = db.Column(db.Float)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User(username=username, password=password, balance=1000)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # VULNERABLE TO SQL INJECTION!
        query = f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'"
        user = db.session.execute(query).first()
        if user:
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', username=username, balance=user.balance)

@app.route('/transfer', methods=['POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    to_account = request.form['to_account']
    amount = float(request.form['amount'])
    from_user = session['username']
    recipient = User.query.filter_by(username=to_account).first()
    if recipient:
        sender = User.query.filter_by(username=from_user).first()
        sender.balance -= amount
        recipient.balance += amount
        trans = Transaction(from_user=from_user, to_user=to_account, amount=amount)
        db.session.add(trans)
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template('search.html', query=query)

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return render_template('profile.html', user=user)
    return "User not found"

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password='admin123', balance=999999)
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True, host='0.0.0.0', port=5000)
EOF