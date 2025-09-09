"""
Tounfite Souk - Single-file Flask app
Features added:
- Register/login with email+password and role (seller/buyer)
- Email verification (token link or printed to console if SMTP not configured)
- Sellers can upload images from their PC (saved to static/uploads)
- Buyers and Sellers can exchange messages (in-app messaging)
- Theme toggle (light/dark) stored in session
- Arabic/English language toggle (simple i18n via dictionaries)
- App renamed to "Tounfite Souk"

Usage (local dev):
1. Save this file as tounfite_souk.py
2. Create and activate venv, install requirements (see requirements list below)
3. Initialize DB: python tounfite_souk.py initdb
4. Run: python tounfite_souk.py

Notes on Email Verification:
- Configure SMTP via environment variables: MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, MAIL_USE_TLS
- If SMTP not configured, verification email content will be printed to console (safe for testing)

Requirements (add to requirements.txt):
flask
flask-login
flask-sqlalchemy
werkzeug
itsdangerous
flask-mail
python-dotenv

"""
from flask import Flask, render_template, redirect, url_for, request, flash, abort, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from datetime import datetime
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'market.db')
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure upload folder exists
Path(UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)
Path(TEMPLATES_DIR).mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change_this_secret_in_prod')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Mail config (optional)
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT') or 0)
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS','False').lower() in ('1','true','yes')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

# Initialize
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Serializer for tokens
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Simple i18n dictionaries
I18N = {
    'en': {
        'app_name': 'Tounfite Souk',
        'welcome': 'Welcome to Tounfite Souk',
        'register': 'Register',
        'login': 'Login',
        'logout': 'Logout',
        'add_item': 'Add Item',
        'my_account': 'My Account',
        'items': 'Items',
        'messages': 'Messages',
        'contact': 'Contact Seller',
    },
    'ar': {
        'app_name': 'سوق تونفيت',
        'welcome': 'مرحبا في سوق تونفيت',
        'register': 'تسجيل',
        'login': 'دخول',
        'logout': 'خروج',
        'add_item': 'أضف سلعة',
        'my_account': 'حسابي',
        'items': 'المنتجات',
        'messages': 'الرسائل',
        'contact': 'اتصال بالبائع',
    }
}

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='buyer')  # 'seller' or 'buyer'
    name = db.Column(db.String(120))
    phone = db.Column(db.String(50))
    city = db.Column(db.String(120))
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=True)
    description = db.Column(db.Text)
    city = db.Column(db.String(120))
    image_filename = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    seller = db.relationship('User', backref=db.backref('items', lazy=True))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

# --- Login loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helpers ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_verification_email(user):
    token = s.dumps(user.email, salt='email-verify')
    verify_url = url_for('verify_email', token=token, _external=True)
    subject = 'Verify your Tounfite Souk account'
    body = f'Hi {user.name or user.email},

Click to verify your account: {verify_url}

Or use code: {token}

If you did not register, ignore.'
    if app.config.get('MAIL_SERVER'):
        try:
            msg = Message(subject=subject, recipients=[user.email], body=body)
            mail.send(msg)
            print('Verification email sent to', user.email)
        except Exception as e:
            print('Failed to send email via SMTP, printing content instead. Error:', e)
            print('EMAIL BODY:
', body)
    else:
        # Mail not configured -> print token so developer can test
        print('--- Verification Email (DEV) ---')
        print('To:', user.email)
        print(body)
        print('--- End Email ---')

# --- Templates writing (create if missing) ---
BASE_HTML = '''<!doctype html>
<html lang="{{ lang }}" dir="{{ 'rtl' if lang=='ar' else 'ltr' }}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ _('app_name') }}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body.dark { background:#121212; color:#eee }
    .card.dark { background:#1e1e1e; color:#eee }
    .navbar.dark { background:#1a1a1a }
    .theme-toggle { cursor:pointer }
  </style>
</head>
<body class="{{ 'dark' if theme=='dark' else '' }}">
<nav class="navbar navbar-expand-lg navbar-light bg-light mb-3 {{ 'dark' if theme=='dark' else '' }}">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('index') }}">{{ _('app_name') }}</a>
    <div class="collapse navbar-collapse">
      <ul class="navbar-nav ms-auto">
        <li class="nav-item"><a class="nav-link" href="{{ url_for('items') }}">{{ _('items') }}</a></li>
        {% if current_user.is_authenticated %}
          {% if current_user.role == 'seller' %}
            <li class="nav-item"><a class="nav-link" href="{{ url_for('add_item') }}">{{ _('add_item') }}</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('my_items') }}">My Items</a></li>
          {% endif %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('messages') }}">{{ _('messages') }}</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('profile') }}">{{ _('my_account') }}</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">{{ _('logout') }}</a></li>
        {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">{{ _('login') }}</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">{{ _('register') }}</a></li>
        {% endif %}
        <li class="nav-item"><a class="nav-link theme-toggle" href="{{ url_for('toggle_theme') }}">{{ '🌙' if theme=='light' else '☀️' }}</a></li>
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">{{ lang.upper() }}</a>
          <ul class="dropdown-menu dropdown-menu-end">
            <li><a class="dropdown-item" href="{{ url_for('set_lang','en') }}">EN</a></li>
            <li><a class="dropdown-item" href="{{ url_for('set_lang','ar') }}">AR</a></li>
          </ul>
        </li>
      </ul>
    </div>
  </div>
</nav>
<div class="container">
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <div class="alert alert-info">{{ messages[0] }}</div>
    {% endif %}
  {% endwith %}
  {% block content %}{% endblock %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

INDEX_HTML = '''{% extends 'base.html' %}
{% block content %}
  <div class="text-center">
    <h1>{{ _('welcome') }}</h1>
    <p class="lead">{{ _('app_name') }} - Local buy & sell</p>
    <p><a class="btn btn-primary" href="{{ url_for('items') }}">{{ _('items') }}</a></p>
  </div>
{% endblock %}
'''

# Other templates similar to previous version but localized and with upload forms
REGISTER_HTML = '''{% extends 'base.html' %}
{% block content %}
<h2>{{ _('register') }}</h2>
<form method="post">
  <div class="mb-3">
    <label class="form-label">Email</label>
    <input class="form-control" name="email" required>
  </div>
  <div class="mb-3">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password" required>
  </div>
  <div class="mb-3">
    <label class="form-label">Role</label>
    <select name="role" class="form-select">
      <option value="buyer">Buyer</option>
      <option value="seller">Seller</option>
    </select>
  </div>
  <div class="mb-3">
    <label class="form-label">Full name</label>
    <input class="form-control" name="name">
  </div>
  <div class="mb-3">
    <label class="form-label">Phone</label>
    <input class="form-control" name="phone">
  </div>
  <div class="mb-3">
    <label class="form-label">City</label>
    <input class="form-control" name="city">
  </div>
  <button class="btn btn-primary" type="submit">{{ _('register') }}</button>
</form>
{% endblock %}
'''

LOGIN_HTML = '''{% extends 'base.html' %}
{% block content %}
<h2>{{ _('login') }}</h2>
<form method="post">
  <div class="mb-3">
    <label class="form-label">Email</label>
    <input class="form-control" name="email" required>
  </div>
  <div class="mb-3">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password" required>
  </div>
  <button class="btn btn-primary" type="submit">{{ _('login') }}</button>
</form>
{% endblock %}
'''

PROFILE_HTML = '''{% extends 'base.html' %}
{% block content %}
<h2>{{ _('my_account') }}</h2>
<form method="post">
  <div class="mb-3">
    <label class="form-label">Email</label>
    <input class="form-control" name="email" value="{{ current_user.email }}" readonly>
  </div>
  <div class="mb-3">
    <label class="form-label">Full name</label>
    <input class="form-control" name="name" value="{{ current_user.name or '' }}">
  </div>
  <div class="mb-3">
    <label class="form-label">Phone</label>
    <input class="form-control" name="phone" value="{{ current_user.phone or '' }}">
  </div>
  <div class="mb-3">
    <label class="form-label">City</label>
    <input class="form-control" name="city" value="{{ current_user.city or '' }}">
  </div>
  <button class="btn btn-primary" type="submit">Save</button>
</form>
{% endblock %}
'''

ADD_ITEM_HTML = '''{% extends 'base.html' %}
{% block content %}
<h2>{{ _('add_item') }}</h2>
<form method="post" enctype="multipart/form-data">
  <div class="mb-3">
    <label class="form-label">Title</label>
    <input class="form-control" name="title" required>
  </div>
  <div class="mb-3">
    <label class="form-label">Price</label>
    <input class="form-control" name="price" type="number" step="0.01">
  </div>
  <div class="mb-3">
    <label class="form-label">Description</label>
    <textarea class="form-control" name="description"></textarea>
  </div>
  <div class="mb-3">
    <label class="form-label">City</label>
    <input class="form-control" name="city">
  </div>
  <div class="mb-3">
    <label class="form-label">Image (upload)</label>
    <input class="form-control" type="file" name="image">
  </div>
  <button class="btn btn-primary" type="submit">Add</button>
</form>
{% endblock %}
'''

ITEMS_HTML = '''{% extends 'base.html' %}
{% block content %}
<h2>{{ _('items') }}</h2>
<form method="get" class="mb-3">
  <div class="row">
    <div class="col-md-4"><input class="form-control" name="q" placeholder="Search title or description" value="{{ request.args.get('q','') }}"></div>
    <div class="col-md-3"><input class="form-control" name="city" placeholder="City" value="{{ request.args.get('city','') }}"></div>
    <div class="col-md-2"><button class="btn btn-secondary">Filter</button></div>
  </div>
</form>
<div class="row">
  {% for item in items %}
  <div class="col-md-4 mb-3">
    <div class="card h-100 {{ 'dark' if theme=='dark' else '' }}">
      {% if item.image_filename %}
      <img src="{{ url_for('uploaded_file', filename=item.image_filename) }}" class="card-img-top" style="height:200px;object-fit:cover;">
      {% endif %}
      <div class="card-body d-flex flex-column">
        <h5 class="card-title">{{ item.title }}</h5>
        <p class="card-text">{{ item.description[:120] }}</p>
        <p class="mt-auto"><strong>{{ item.price }} MAD</strong></p>
        <p>Seller: {{ item.seller.name or item.seller.email }}</p>
        <p>City: {{ item.city }}</p>
        <p><a class="btn btn-sm btn-outline-primary" href="{{ url_for('contact_seller', seller_id=item.seller.id) }}">{{ _('contact') }}</a></p>
      </div>
    </div>
  </div>
  {% endfor %}
</div>
{% endblock %}
'''

MESSAGES_HTML = '''{% extends 'base.html' %}
{% block content %}
<h2>{{ _('messages') }}</h2>
<div class="row">
  <div class="col-md-4">
    <h5>Conversations</h5>
    <ul class="list-group">
      {% for u in conv_users %}
      <li class="list-group-item"><a href="{{ url_for('messages', with_id=u.id) }}">{{ u.name or u.email }}</a></li>
      {% endfor %}
    </ul>
  </div>
  <div class="col-md-8">
    {% if messages_list is defined %}
      <h5>Conversation with {{ other.name or other.email }}</h5>
      <div class="mb-3">
        {% for m in messages_list %}
          <div class="p-2 mb-2" style="background:#f1f1f1;border-radius:6px">{{ m.sender.name or m.sender.email }}: {{ m.content }}</div>
        {% endfor %}
      </div>
      <form method="post">
        <div class="mb-3"><textarea class="form-control" name="content" required></textarea></div>
        <button class="btn btn-primary">Send</button>
      </form>
    {% else %}
      <p>Select a conversation.</p>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

CONTACT_HTML = '''{% extends 'base.html' %}
{% block content %}
<h2>{{ _('contact') }}</h2>
<form method="post">
  <div class="mb-3"><label class="form-label">Message</label><textarea class="form-control" name="content" required></textarea></div>
  <button class="btn btn-primary">Send</button>
</form>
{% endblock %}
'''

# Write templates if missing
templates = {
    'base.html': BASE_HTML,
    'index.html': INDEX_HTML,
    'register.html': REGISTER_HTML,
    'login.html': LOGIN_HTML,
    'profile.html': PROFILE_HTML,
    'add_item.html': ADD_ITEM_HTML,
    'items.html': ITEMS_HTML,
    'messages.html': MESSAGES_HTML,
    'contact.html': CONTACT_HTML,
}
for name, content in templates.items():
    path = os.path.join(TEMPLATES_DIR, name)
    if not os.path.isfile(path):
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

# --- i18n helper ---
def get_lang():
    lang = session.get('lang', os.getenv('DEFAULT_LANG','en'))
    if lang not in I18N: lang = 'en'
    return lang

def _(key):
    lang = get_lang()
    return I18N.get(lang, I18N['en']).get(key, key)

@app.context_processor
def inject_globals():
    return dict(_=_, lang=get_lang(), theme=session.get('theme','light'))

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/set_lang/<lang>')
def set_lang(lang):
    if lang in I18N:
        session['lang'] = lang
    return redirect(request.referrer or url_for('index'))

@app.route('/toggle_theme')
def toggle_theme():
    session['theme'] = 'dark' if session.get('theme','light')=='light' else 'light'
    return redirect(request.referrer or url_for('index'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password')
        role = request.form.get('role') or 'buyer'
        name = request.form.get('name')
        phone = request.form.get('phone')
        city = request.form.get('city')
        if not email or not password:
            flash('Email and password are required')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('register'))
        user = User(email=email, role=role, name=name, phone=phone, city=city, verified=False)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)
        login_user(user)
        flash('Registered. A verification email was sent (or printed to console).')
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-verify', max_age=60*60*24)
    except Exception as e:
        flash('Invalid or expired token')
        return redirect(url_for('index'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found')
        return redirect(url_for('index'))
    user.verified = True
    db.session.commit()
    flash('Email verified — thank you!')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash('Invalid credentials')
            return redirect(url_for('login'))
        login_user(user)
        flash('Logged in')
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out')
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.name = request.form.get('name')
        current_user.phone = request.form.get('phone')
        current_user.city = request.form.get('city')
        db.session.commit()
        flash('Profile updated')
        return redirect(url_for('profile'))
    return render_template('profile.html')

@app.route('/add_item', methods=['GET','POST'])
@login_required
def add_item():
    if current_user.role != 'seller':
        abort(403)
    if request.method == 'POST':
        title = request.form.get('title')
        price = request.form.get('price') or 0
        description = request.form.get('description')
        city = request.form.get('city')
        image = request.files.get('image')
        filename = None
        if image and allowed_file(image.filename):
            fname = secure_filename(image.filename)
            # make unique
            timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
            filename = f"{current_user.id}_{timestamp}_{fname}"
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        item = Item(title=title, price=float(price), description=description, city=city, image_filename=filename, seller=current_user)
        db.session.add(item)
        db.session.commit()
        flash('Item added')
        return redirect(url_for('my_items'))
    return render_template('add_item.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/items')
def items():
    q = request.args.get('q', '').strip()
    city = request.args.get('city', '').strip()
    items_q = Item.query.order_by(Item.created_at.desc())
    if q:
        items_q = items_q.filter((Item.title.contains(q)) | (Item.description.contains(q)))
    if city:
        items_q = items_q.filter(Item.city.contains(city))
    items_list = items_q.all()
    return render_template('items.html', items=items_list)

@app.route('/my_items')
@login_required
def my_items():
    if current_user.role != 'seller':
        abort(403)
    items_list = Item.query.filter_by(seller_id=current_user.id).order_by(Item.created_at.desc()).all()
    return render_template('items.html', items=items_list)

@app.route('/contact/<int:seller_id>', methods=['GET','POST'])
@login_required
def contact_seller(seller_id):
    seller = User.query.get_or_404(seller_id)
    if request.method == 'POST':
        content = request.form.get('content')
        if not content:
            flash('Message cannot be empty')
            return redirect(url_for('contact_seller', seller_id=seller_id))
        m = Message(sender_id=current_user.id, receiver_id=seller.id, content=content)
        db.session.add(m)
        db.session.commit()
        flash('Message sent')
        return redirect(url_for('messages'))
    return render_template('contact.html')

@app.route('/messages', methods=['GET','POST'])
@login_required
def messages():
    # list conversation partners
    # partners: users who sent or received messages with current_user
    partners = set()
    for m in Message.query.filter((Message.sender_id==current_user.id) | (Message.receiver_id==current_user.id)).all():
        partners.add(m.sender_id if m.sender_id!=current_user.id else m.receiver_id)
    conv_users = User.query.filter(User.id.in_(list(partners))).all() if partners else []

    other = None
    messages_list = None
    with_id = request.args.get('with_id')
    if with_id:
        other = User.query.get(int(with_id))
        if other:
            messages_list = Message.query.filter(
                ((Message.sender_id==current_user.id)&(Message.receiver_id==other.id))|
                ((Message.sender_id==other.id)&(Message.receiver_id==current_user.id))
            ).order_by(Message.created_at).all()
    if request.method == 'POST' and other:
        content = request.form.get('content')
        if content:
            m = Message(sender_id=current_user.id, receiver_id=other.id, content=content)
            db.session.add(m)
            db.session.commit()
            return redirect(url_for('messages', with_id=other.id))
    return render_template('messages.html', conv_users=conv_users, messages_list=messages_list, other=other)

# --- CLI to init DB ---
@app.cli.command('initdb')
def initdb_command():
    db.create_all()
    print('Initialized the database.')

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'initdb':
        with app.app_context():
            db.create_all()
            print('Database created at', DB_PATH)
    else:
        app.run(debug=True)
