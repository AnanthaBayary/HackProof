from flask import Flask, request, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.secret_key = "learn_cybersecurity_2024"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(120))
    balance = db.Column(db.Float, default=1000.0)

# ========== ROUTES ==========

@app.route('/')
def index():
    """Homepage showing all vulnerabilities"""
    mode = request.args.get('mode', 'vulnerable')
    return render_template('index.html', mode=mode)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page - vulnerable to XSS"""
    mode = request.args.get('mode', 'vulnerable')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if user exists
        existing = User.query.filter_by(username=username).first()
        if existing:
            return "Username already exists! <a href='/register'>Try again</a>"
        
        # Create user (password stored in plaintext - VULNERABLE!)
        user = User(username=username, password=password, balance=1000)
        db.session.add(user)
        db.session.commit()
        
        return redirect(url_for('login', mode=mode))
    
    return render_template('register.html', mode=mode)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - vulnerable to SQL Injection"""
    mode = request.args.get('mode', 'vulnerable')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        mode = request.form.get('mode', 'vulnerable')
        
        if mode == 'vulnerable':
            # 🔴 VULNERABLE: SQL Injection possible!
            query = f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'"
            result = db.session.execute(query).first()
        else:
            # 🟢 SECURE: Parameterized query
            result = User.query.filter_by(username=username, password=password).first()
        
        if result:
            session['user_id'] = result.id
            session['username'] = result.username
            return redirect(url_for('dashboard', mode=mode))
        else:
            return render_template('login.html', mode=mode, error="Invalid credentials!")
    
    return render_template('login.html', mode=mode)

@app.route('/dashboard')
def dashboard():
    """Dashboard showing user info and transfer form"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    mode = request.args.get('mode', 'vulnerable')
    user = User.query.get(session['user_id'])
    
    return render_template('dashboard.html', 
                         username=user.username, 
                         balance=user.balance, 
                         mode=mode)

@app.route('/transfer', methods=['POST'])
def transfer():
    """Transfer money - vulnerable to negative amount bug"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    mode = request.args.get('mode', 'vulnerable')
    to_account = request.form['to_account']
    amount = float(request.form['amount'])
    from_user = session['username']
    
    if mode == 'vulnerable':
        # 🔴 VULNERABLE: No validation on amount!
        # Can transfer negative amounts to increase balance
        recipient = User.query.filter_by(username=to_account).first()
        if recipient:
            sender = User.query.filter_by(username=from_user).first()
            sender.balance -= amount
            recipient.balance += amount
            db.session.commit()
    else:
        # 🟢 SECURE: Validate amount
        if amount <= 0 or amount > 10000:
            return "Invalid amount! <a href='/dashboard'>Go back</a>"
        recipient = User.query.filter_by(username=to_account).first()
        if recipient:
            sender = User.query.filter_by(username=from_user).first()
            if sender.balance >= amount:
                sender.balance -= amount
                recipient.balance += amount
                db.session.commit()
            else:
                return "Insufficient funds! <a href='/dashboard'>Go back</a>"
    
    return redirect(url_for('dashboard', mode=mode))

@app.route('/profile/<username>')
def profile(username):
    """Profile page - vulnerable to IDOR"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    mode = request.args.get('mode', 'vulnerable')
    
    if mode == 'vulnerable':
        # 🔴 VULNERABLE: Anyone can view any profile
        user = User.query.filter_by(username=username).first()
    else:
        # 🟢 SECURE: Only view own profile
        if username != session['username']:
            return "Access Denied! You can only view your own profile."
        user = User.query.filter_by(username=username).first()
    
    if user:
        return render_template('profile.html', user=user, mode=mode)
    return "User not found"

@app.route('/search')
def search():
    """Search page - vulnerable to XSS"""
    mode = request.args.get('mode', 'vulnerable')
    query = request.args.get('q', '')
    
    return render_template('search.html', query=query, mode=mode)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ========== CREATE DATABASE ==========

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin user
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password='admin123', balance=999999)
            db.session.add(admin)
            db.session.commit()
        # Create test users
        if not User.query.filter_by(username='alice').first():
            alice = User(username='alice', password='alice123', balance=5000)
            db.session.add(alice)
            db.session.commit()
        if not User.query.filter_by(username='bob').first():
            bob = User(username='bob', password='bob123', balance=3000)
            db.session.add(bob)
            db.session.commit()
    
    app.run(debug=True, host='0.0.0.0', port=5000)