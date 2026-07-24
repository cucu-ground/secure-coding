import os
import re
import sqlite3
import time
import uuid
from datetime import timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from flask_socketio import SocketIO, disconnect, emit
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'

DATABASE = os.environ.get('DATABASE_PATH', 'market.db')
socketio = SocketIO(app, manage_session=False)

USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,20}$')
UUID_RE = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)
FAILED_LOGIN_LIMIT = 5
FAILED_LOGIN_WINDOW = 10 * 60
REPORT_LIMIT_PER_HOUR = 5
CHAT_LIMIT_PER_10_SECONDS = 5
REPORT_BLOCK_THRESHOLD = 3
INITIAL_BALANCE = 100000
CHAT_TIMESTAMPS = {}


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def column_exists(cursor, table, column):
    cursor.execute(f"PRAGMA table_info({table})")
    return any(row['name'] == column for row in cursor.fetchall())


def add_column_if_missing(cursor, table, column, definition):
    if not column_exists(cursor, table, column):
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_suspended INTEGER NOT NULL DEFAULT 0,
                balance INTEGER NOT NULL DEFAULT 100000
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price INTEGER NOT NULL,
                image_url TEXT,
                seller_id TEXT NOT NULL,
                is_blocked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (seller_id) REFERENCES user(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (reporter_id) REFERENCES user(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                action TEXT NOT NULL,
                target_id TEXT,
                created_at INTEGER NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS private_message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (sender_id) REFERENCES user(id),
                FOREIGN KEY (receiver_id) REFERENCES user(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS money_transfer (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (sender_id) REFERENCES user(id),
                FOREIGN KEY (receiver_id) REFERENCES user(id)
            )
        """)

        add_column_if_missing(cursor, 'user', 'is_admin', 'INTEGER NOT NULL DEFAULT 0')
        add_column_if_missing(cursor, 'user', 'is_suspended', 'INTEGER NOT NULL DEFAULT 0')
        add_column_if_missing(cursor, 'user', 'balance', f'INTEGER NOT NULL DEFAULT {INITIAL_BALANCE}')
        add_column_if_missing(cursor, 'product', 'image_url', 'TEXT')
        add_column_if_missing(cursor, 'product', 'is_blocked', 'INTEGER NOT NULL DEFAULT 0')
        add_column_if_missing(cursor, 'report', 'created_at', 'INTEGER NOT NULL DEFAULT 0')
        db.commit()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = current_user()
        if not user or user['is_suspended']:
            session.clear()
            flash('휴면 처리된 계정입니다. 관리자에게 문의해주세요.')
            return redirect(url_for('login'))
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped_view(*args, **kwargs):
        user = current_user()
        if not user or not user['is_admin']:
            abort(403)
        return view(*args, **kwargs)

    return wrapped_view


def current_user():
    if 'user_id' not in session:
        return None
    cursor = get_db().cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    return cursor.fetchone()


def create_csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = uuid.uuid4().hex
        session['csrf_token'] = token
    return token


app.jinja_env.globals['csrf_token'] = create_csrf_token


@app.context_processor
def inject_nav_user():
    return {'nav_user': current_user()}


def validate_csrf():
    form_token = request.form.get('csrf_token', '')
    if not form_token or form_token != session.get('csrf_token'):
        abort(400)


def clean_text(value, min_len, max_len, field_name):
    value = (value or '').strip()
    if len(value) < min_len or len(value) > max_len:
        raise ValueError(f'{field_name} 길이가 올바르지 않습니다.')
    return value


def validate_username(username):
    username = (username or '').strip()
    if not USERNAME_RE.fullmatch(username):
        raise ValueError('사용자명은 영문, 숫자, 밑줄(_) 3~20자만 사용할 수 있습니다.')
    return username


def validate_password(password):
    if not password or len(password) < 8 or len(password) > 72:
        raise ValueError('비밀번호는 8~72자로 입력해야 합니다.')
    if not re.search(r'[A-Za-z]', password) or not re.search(r'[0-9]', password):
        raise ValueError('비밀번호에는 영문자와 숫자가 모두 포함되어야 합니다.')
    return password


def validate_price(price):
    price = (price or '').strip()
    if not price.isdigit():
        raise ValueError('가격은 숫자만 입력할 수 있습니다.')
    price_int = int(price)
    if price_int < 0 or price_int > 100000000:
        raise ValueError('가격 범위가 올바르지 않습니다.')
    return price_int


def validate_amount(amount):
    amount_int = validate_price(amount)
    if amount_int <= 0:
        raise ValueError('송금액은 1원 이상이어야 합니다.')
    return amount_int


def validate_url(value):
    value = (value or '').strip()
    if not value:
        return ''
    if len(value) > 300:
        raise ValueError('사진 URL은 300자 이하로 입력해야 합니다.')
    parsed = urlparse(value)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        raise ValueError('사진 URL은 http 또는 https 주소여야 합니다.')
    return value


def validate_uuid(value, field_name):
    value = (value or '').strip()
    if not UUID_RE.fullmatch(value):
        raise ValueError(f'{field_name} 형식이 올바르지 않습니다.')
    return value


def require_uuid(value, field_name):
    try:
        return validate_uuid(value, field_name)
    except ValueError:
        abort(404)


def add_audit_log(user_id, action, target_id=None):
    cursor = get_db().cursor()
    cursor.execute(
        "INSERT INTO audit_log (id, user_id, action, target_id, created_at) VALUES (?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), user_id, action, target_id, int(time.time())),
    )


def apply_report_penalty(cursor, target_id):
    cursor.execute("SELECT COUNT(*) AS count FROM report WHERE target_id = ?", (target_id,))
    report_count = cursor.fetchone()['count']
    if report_count < REPORT_BLOCK_THRESHOLD:
        return None

    cursor.execute("UPDATE product SET is_blocked = 1 WHERE id = ?", (target_id,))
    if cursor.rowcount:
        return 'product_blocked'

    cursor.execute("UPDATE user SET is_suspended = 1 WHERE id = ? AND is_admin = 0", (target_id,))
    if cursor.rowcount:
        return 'user_suspended'
    return None


@app.before_request
def refresh_session_timeout():
    session.permanent = True
    now = int(time.time())
    last_seen = session.get('last_seen')
    if last_seen and now - last_seen > app.permanent_session_lifetime.total_seconds():
        session.clear()
        flash('세션이 만료되었습니다. 다시 로그인해주세요.')
        return redirect(url_for('login'))
    session['last_seen'] = now


@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "connect-src 'self' ws: wss:; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' http: https: data:; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


@app.errorhandler(400)
def bad_request(error):
    return render_template('error.html', message='잘못된 요청입니다.'), 400


@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html', message='권한이 없습니다.'), 403


@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', message='페이지를 찾을 수 없습니다.'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message='일시적인 오류가 발생했습니다.'), 500


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        validate_csrf()
        try:
            username = validate_username(request.form.get('username'))
            password = validate_password(request.form.get('password'))
        except ValueError as error:
            flash(str(error))
            return redirect(url_for('register'))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) AS count FROM user")
        is_first_user = cursor.fetchone()['count'] == 0
        cursor.execute("SELECT id FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        password_hash = generate_password_hash(password)
        cursor.execute(
            """
            INSERT INTO user (id, username, password, is_admin, balance)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, username, password_hash, 1 if is_first_user else 0, INITIAL_BALANCE),
        )
        add_audit_log(user_id, 'register')
        db.commit()
        flash('회원가입이 완료되었습니다. 첫 번째 가입자는 관리자로 지정됩니다.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        validate_csrf()
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        now = int(time.time())
        attempts = session.get('failed_logins', [])
        attempts = [attempt for attempt in attempts if now - attempt < FAILED_LOGIN_WINDOW]

        if len(attempts) >= FAILED_LOGIN_LIMIT:
            flash('로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.')
            return redirect(url_for('login'))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and user['is_suspended']:
            flash('휴면 처리된 계정입니다. 관리자에게 문의해주세요.')
            return redirect(url_for('login'))
        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['last_seen'] = now
            create_csrf_token()
            add_audit_log(user['id'], 'login')
            db.commit()
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))

        attempts.append(now)
        session['failed_logins'] = attempts
        flash('아이디 또는 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        add_audit_log(user_id, 'logout')
        get_db().commit()
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    db = get_db()
    cursor = db.cursor()
    q = (request.args.get('q') or '').strip()
    if len(q) > 80:
        q = q[:80]
    if q:
        keyword = f'%{q}%'
        cursor.execute(
            """
            SELECT product.*, user.username AS seller_username
            FROM product
            JOIN user ON user.id = product.seller_id
            WHERE product.is_blocked = 0
              AND (product.title LIKE ? OR product.description LIKE ?)
            ORDER BY product.rowid DESC
            """,
            (keyword, keyword),
        )
    else:
        cursor.execute("""
            SELECT product.*, user.username AS seller_username
            FROM product
            JOIN user ON user.id = product.seller_id
            WHERE product.is_blocked = 0
            ORDER BY product.rowid DESC
        """)
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user(), q=q)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    cursor = db.cursor()
    user = current_user()
    if request.method == 'POST':
        validate_csrf()
        action = request.form.get('action')
        try:
            if action == 'password':
                current_password = request.form.get('current_password') or ''
                new_password = validate_password(request.form.get('new_password'))
                if not check_password_hash(user['password'], current_password):
                    raise ValueError('현재 비밀번호가 올바르지 않습니다.')
                cursor.execute(
                    "UPDATE user SET password = ? WHERE id = ?",
                    (generate_password_hash(new_password), session['user_id']),
                )
                add_audit_log(session['user_id'], 'password_update')
                flash('비밀번호가 변경되었습니다.')
            else:
                bio = clean_text(request.form.get('bio', ''), 0, 300, '소개글')
                cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
                add_audit_log(session['user_id'], 'profile_update')
                flash('프로필이 업데이트되었습니다.')
        except ValueError as error:
            flash(str(error))
            return redirect(url_for('profile'))

        db.commit()
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)


@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        validate_csrf()
        try:
            title = clean_text(request.form.get('title'), 1, 80, '제목')
            description = clean_text(request.form.get('description'), 1, 1000, '설명')
            price = validate_price(request.form.get('price'))
            image_url = validate_url(request.form.get('image_url'))
        except ValueError as error:
            flash(str(error))
            return redirect(url_for('new_product'))

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            """
            INSERT INTO product (id, title, description, price, image_url, seller_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (product_id, title, description, price, image_url, session['user_id']),
        )
        add_audit_log(session['user_id'], 'product_create', product_id)
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')


@app.route('/product/<product_id>')
def view_product(product_id):
    product_id = require_uuid(product_id, '상품 ID')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        abort(404)
    user = current_user()
    if product['is_blocked'] and (not user or (product['seller_id'] != user['id'] and not user['is_admin'])):
        abort(404)
    cursor.execute("SELECT id, username, bio FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller, user=user)


@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product_id = require_uuid(product_id, '상품 ID')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        abort(404)
    if product['seller_id'] != session['user_id']:
        abort(403)

    if request.method == 'POST':
        validate_csrf()
        try:
            title = clean_text(request.form.get('title'), 1, 80, '제목')
            description = clean_text(request.form.get('description'), 1, 1000, '설명')
            price = validate_price(request.form.get('price'))
            image_url = validate_url(request.form.get('image_url'))
        except ValueError as error:
            flash(str(error))
            return redirect(url_for('edit_product', product_id=product_id))

        cursor.execute(
            """
            UPDATE product
            SET title = ?, description = ?, price = ?, image_url = ?
            WHERE id = ? AND seller_id = ?
            """,
            (title, description, price, image_url, product_id, session['user_id']),
        )
        add_audit_log(session['user_id'], 'product_update', product_id)
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    return render_template('edit_product.html', product=product)


@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    validate_csrf()
    product_id = require_uuid(product_id, '상품 ID')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        abort(404)
    if product['seller_id'] != session['user_id']:
        abort(403)

    cursor.execute("DELETE FROM product WHERE id = ? AND seller_id = ?", (product_id, session['user_id']))
    add_audit_log(session['user_id'], 'product_delete', product_id)
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))


@app.route('/messages', methods=['GET'])
@login_required
def messages():
    cursor = get_db().cursor()
    cursor.execute(
        "SELECT id, username FROM user WHERE id != ? AND is_suspended = 0 ORDER BY username",
        (session['user_id'],),
    )
    return render_template('messages.html', users=cursor.fetchall())


@app.route('/messages/<receiver_id>', methods=['GET', 'POST'])
@login_required
def private_messages(receiver_id):
    receiver_id = require_uuid(receiver_id, '사용자 ID')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username FROM user WHERE id = ? AND is_suspended = 0", (receiver_id,))
    receiver = cursor.fetchone()
    if not receiver or receiver['id'] == session['user_id']:
        abort(404)

    if request.method == 'POST':
        validate_csrf()
        try:
            message = clean_text(request.form.get('message'), 1, 500, '메시지')
        except ValueError as error:
            flash(str(error))
            return redirect(url_for('private_messages', receiver_id=receiver_id))
        cursor.execute(
            """
            INSERT INTO private_message (id, sender_id, receiver_id, message, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), session['user_id'], receiver_id, message, int(time.time())),
        )
        add_audit_log(session['user_id'], 'private_message', receiver_id)
        db.commit()
        return redirect(url_for('private_messages', receiver_id=receiver_id))

    cursor.execute(
        """
        SELECT private_message.*, sender.username AS sender_username
        FROM private_message
        JOIN user AS sender ON sender.id = private_message.sender_id
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY created_at ASC
        """,
        (session['user_id'], receiver_id, receiver_id, session['user_id']),
    )
    return render_template('private_messages.html', receiver=receiver, messages=cursor.fetchall())


@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        validate_csrf()
        try:
            receiver_username = validate_username(request.form.get('receiver_username'))
            amount = validate_amount(request.form.get('amount'))
        except ValueError as error:
            flash(str(error))
            return redirect(url_for('transfer'))

        sender = current_user()
        cursor.execute(
            "SELECT id, username FROM user WHERE username = ? AND is_suspended = 0",
            (receiver_username,),
        )
        receiver = cursor.fetchone()
        if not receiver or receiver['id'] == sender['id']:
            flash('송금 대상이 올바르지 않습니다.')
            return redirect(url_for('transfer'))
        if sender['balance'] < amount:
            flash('잔액이 부족합니다.')
            return redirect(url_for('transfer'))

        cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, sender['id']))
        cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver['id']))
        cursor.execute(
            """
            INSERT INTO money_transfer (id, sender_id, receiver_id, amount, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), sender['id'], receiver['id'], amount, int(time.time())),
        )
        add_audit_log(sender['id'], 'money_transfer', receiver['id'])
        db.commit()
        flash('송금이 완료되었습니다.')
        return redirect(url_for('transfer'))

    cursor.execute(
        """
        SELECT money_transfer.*, sender.username AS sender_username, receiver.username AS receiver_username
        FROM money_transfer
        JOIN user AS sender ON sender.id = money_transfer.sender_id
        JOIN user AS receiver ON receiver.id = money_transfer.receiver_id
        WHERE sender_id = ? OR receiver_id = ?
        ORDER BY created_at DESC
        """,
        (session['user_id'], session['user_id']),
    )
    return render_template('transfer.html', user=current_user(), transfers=cursor.fetchall())


@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        validate_csrf()
        try:
            target_id = validate_uuid(request.form.get('target_id'), '신고 대상')
            reason = clean_text(request.form.get('reason'), 5, 500, '신고 사유')
        except ValueError as error:
            flash(str(error))
            return redirect(url_for('report'))

        db = get_db()
        cursor = db.cursor()
        now = int(time.time())
        cursor.execute(
            "SELECT COUNT(*) AS count FROM report WHERE reporter_id = ? AND created_at > ?",
            (session['user_id'], now - 3600),
        )
        if cursor.fetchone()['count'] >= REPORT_LIMIT_PER_HOUR:
            flash('신고는 1시간에 5회까지만 접수할 수 있습니다.')
            return redirect(url_for('report'))

        cursor.execute(
            "SELECT id FROM report WHERE reporter_id = ? AND target_id = ?",
            (session['user_id'], target_id),
        )
        if cursor.fetchone():
            flash('이미 신고한 대상입니다.')
            return redirect(url_for('report'))

        cursor.execute("SELECT id FROM product WHERE id = ? UNION SELECT id FROM user WHERE id = ?", (target_id, target_id))
        if not cursor.fetchone():
            flash('존재하지 않는 신고 대상입니다.')
            return redirect(url_for('report'))

        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason, created_at) VALUES (?, ?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason, now),
        )
        penalty = apply_report_penalty(cursor, target_id)
        add_audit_log(session['user_id'], 'report_create', target_id)
        if penalty:
            add_audit_log(None, penalty, target_id)
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')


@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        validate_csrf()
        action = request.form.get('action')
        target_id = require_uuid(request.form.get('target_id'), '대상 ID')
        if action == 'block_product':
            cursor.execute("UPDATE product SET is_blocked = 1 WHERE id = ?", (target_id,))
        elif action == 'unblock_product':
            cursor.execute("UPDATE product SET is_blocked = 0 WHERE id = ?", (target_id,))
        elif action == 'suspend_user':
            cursor.execute("UPDATE user SET is_suspended = 1 WHERE id = ? AND is_admin = 0", (target_id,))
        elif action == 'activate_user':
            cursor.execute("UPDATE user SET is_suspended = 0 WHERE id = ?", (target_id,))
        else:
            abort(400)
        add_audit_log(session['user_id'], action, target_id)
        db.commit()
        flash('관리자 작업이 처리되었습니다.')
        return redirect(url_for('admin'))

    cursor.execute("SELECT id, username, is_admin, is_suspended, balance FROM user ORDER BY username")
    users = cursor.fetchall()
    cursor.execute("""
        SELECT product.*, user.username AS seller_username
        FROM product JOIN user ON user.id = product.seller_id
        ORDER BY product.rowid DESC
    """)
    products = cursor.fetchall()
    cursor.execute("""
        SELECT report.*, reporter.username AS reporter_username
        FROM report JOIN user AS reporter ON reporter.id = report.reporter_id
        ORDER BY report.created_at DESC
    """)
    reports = cursor.fetchall()
    return render_template('admin.html', users=users, products=products, reports=reports)


@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        disconnect()


@socketio.on('send_message')
def handle_send_message_event(data):
    if 'user_id' not in session:
        disconnect()
        return
    if not isinstance(data, dict):
        return

    now = int(time.time())
    user_id = session['user_id']
    timestamps = CHAT_TIMESTAMPS.get(user_id, [])
    timestamps = [item for item in timestamps if now - item < 10]
    if len(timestamps) >= CHAT_LIMIT_PER_10_SECONDS:
        CHAT_TIMESTAMPS[user_id] = timestamps
        emit('message', {'username': 'system', 'message': '메시지를 너무 빠르게 보내고 있습니다.'})
        return

    try:
        message = clean_text(str(data.get('message', '')), 1, 300, '메시지')
    except ValueError:
        emit('message', {'username': 'system', 'message': '메시지 길이가 올바르지 않습니다.'})
        return
    user = current_user()
    if not user:
        disconnect()
        return

    timestamps.append(now)
    CHAT_TIMESTAMPS[user_id] = timestamps
    emit(
        'message',
        {
            'message_id': str(uuid.uuid4()),
            'username': str(escape(user['username'])),
            'message': str(escape(message)),
        },
        broadcast=True,
    )


if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=False)
