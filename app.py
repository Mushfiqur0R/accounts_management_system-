
import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort, Response, send_from_directory
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
import io, csv, pandas as pd
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.sql import func, extract
from sqlalchemy import case, literal_column
from dotenv import load_dotenv
from collections import defaultdict
import calendar
from dateutil.relativedelta import relativedelta


# .env ফাইল থেকে ভেরিয়েবল লোড করুন
load_dotenv()

app = Flask(__name__)

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///local_database.db').replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-strong-and-random-secret-key')

# --- File Upload Configuration ---
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'persistent_uploads')
MONOGRAM_UPLOAD_FOLDER = os.path.join(UPLOAD_DIR, 'monograms')
TRANSACTION_UPLOAD_FOLDER = os.path.join(UPLOAD_DIR, 'csv_imports')

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
ALLOWED_CSV_EXTENSIONS = {'csv'}

for folder in [MONOGRAM_UPLOAD_FOLDER, TRANSACTION_UPLOAD_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# --- Initialize Extensions ---
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "info"


# --- SQLAlchemy Models ---
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

class Client(db.Model):
    __tablename__ = 'clients'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    contact_number = db.Column(db.String(50), nullable=True)
    transactions = db.relationship('Transaction', backref='client', lazy=True, cascade="all, delete-orphan")

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('clients.id'), nullable=False)
    transaction_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    fabrics_type = db.Column(db.String(100), nullable=True)
    design_code = db.Column(db.String(100), nullable=True)
    qty = db.Column(db.Float, nullable=True)
    transaction_mode = db.Column(db.String(50), nullable=True)
    narration = db.Column(db.Text, nullable=True)
    chq_no = db.Column(db.String(50), nullable=True)
    challan_voucher_no = db.Column(db.String(100), nullable=True)
    debit = db.Column(db.Float, default=0.0)
    credit = db.Column(db.Float, default=0.0)

class CompanyDetails(db.Model):
    __tablename__ = 'company_details'
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(200), nullable=True)
    monogram_path = db.Column(db.String(200), nullable=True)
    address = db.Column(db.Text, nullable=True)
    contact_info = db.Column(db.String(200), nullable=True)

class ConveyanceBill(db.Model):
    __tablename__ = 'conveyance_bills'
    id = db.Column(db.Integer, primary_key=True)
    bill_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    person_name = db.Column(db.String(100), nullable=False)
    from_location = db.Column(db.String(200), nullable=True)
    to_location = db.Column(db.String(200), nullable=True)
    purpose = db.Column(db.Text, nullable=True)
    amount = db.Column(db.Float, nullable=False)

class DailyProduction(db.Model):
    __tablename__ = 'daily_production'
    id = db.Column(db.Integer, primary_key=True)
    production_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    machine_number = db.Column(db.String(50), nullable=False)
    design_number = db.Column(db.String(100), nullable=False)
    client_name = db.Column(db.String(150), nullable=True)
    total_production = db.Column(db.Float, nullable=False)
    production_unit = db.Column(db.String(50), nullable=False, default='yards')

class InventoryItem(db.Model):
    __tablename__ = 'inventory_items'
    id = db.Column(db.Integer, primary_key=True)
    product_type = db.Column(db.String(100), nullable=False)
    sub_type = db.Column(db.String(150), nullable=False)
    default_unit = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=True)
    transactions = db.relationship('InventoryTransaction', backref='item', lazy='dynamic', cascade="all, delete-orphan")
    __table_args__ = (db.UniqueConstraint('product_type', 'sub_type', name='_product_subtype_uc'),)

class InventoryTransaction(db.Model):
    __tablename__ = 'inventory_transactions'
    id = db.Column(db.Integer, primary_key=True)
    transaction_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    transaction_type = db.Column(db.String(10), nullable=False) # 'IN' or 'OUT'
    inventory_item_id = db.Column(db.Integer, db.ForeignKey('inventory_items.id'), nullable=False)
    product_type = db.Column(db.String(100), nullable=False)
    sub_type = db.Column(db.String(150), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(50), nullable=False)
    total_price = db.Column(db.Float, nullable=True)
    client_name = db.Column(db.String(150), nullable=True)
    remarks = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)


# --- Flask-Login user_loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- Jinja Custom Filter ---
def datetimeformat(value, format_str='%Y-%m-%d'): # Changed default format
    if not value: return ""
    if isinstance(value, str) and value.lower() == 'now':
        return datetime.now().strftime(format_str)
    if isinstance(value, datetime):
        return value.strftime(format_str)
    try:
        # Attempt to parse date string if needed
        dt_obj = datetime.fromisoformat(str(value))
        return dt_obj.strftime(format_str)
    except (ValueError, TypeError):
        return value
app.jinja_env.filters['datetimeformat'] = datetimeformat

# --- Context Processor ---
@app.context_processor
def inject_global_vars():
    company_details = db.session.get(CompanyDetails, 1)
    return dict(company_details=company_details, _year=datetime.utcnow().year, current_user=current_user)

# --- File Upload Route ---
@app.route('/uploads/monograms/<filename>')
def uploaded_monogram(filename):
    return send_from_directory(MONOGRAM_UPLOAD_FOLDER, filename)
    
# --- Custom Decorator for Admin Access ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


# --- Authentication Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    user_count = db.session.query(func.count(User.id)).scalar()
    
    if request.method == 'POST':
        if user_count > 0:
            flash('Public registration is closed. Please contact an administrator.', 'warning')
            return redirect(url_for('login'))

        username = request.form['username']
        password = request.form['password']
        
        is_first_admin = (user_count == 0)
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password, is_admin=is_first_admin)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Admin registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
        
    registration_allowed = (user_count == 0)
    return render_template('register.html', registration_allowed=registration_allowed, user_count=user_count)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    user_count = db.session.query(func.count(User.id)).scalar()
    registration_allowed = (user_count == 0)

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid username or password.', 'error')
            return render_template('login.html', username=username, registration_allowed=registration_allowed)
        else:
            login_user(user, remember=remember)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
    
    return render_template('login.html', registration_allowed=registration_allowed)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# app.py - Part 2: Client Management & Dashboard Routes

# --- Main Dashboard ---
@app.route('/')
@login_required
def index():
    # --- Client Balances and Total Receivables ---
    clients_with_balances = db.session.query(
        Client.id, Client.name, Client.contact_number,
        (func.coalesce(func.sum(Transaction.debit), 0) - func.coalesce(func.sum(Transaction.credit), 0)).label('balance')
    ).outerjoin(Transaction).group_by(Client.id).order_by(db.desc('balance')).all()
    
    total_receivables = sum(client.balance for client in clients_with_balances)
    top_clients_data = sorted([c for c in clients_with_balances if c.balance > 0], key=lambda x: x.balance, reverse=True)[:5]
    top_clients_labels = [client.name for client in top_clients_data]
    top_clients_values = [client.balance for client in top_clients_data]

    # --- Chart Data: Monthly Conveyance Expenses (Last 6 Months) ---
    today = datetime.today()
    monthly_expenses_labels = []
    expenses_by_month = defaultdict(float)
    
    for i in range(5, -1, -1):
        target_date = today - relativedelta(months=i)
        month_label = target_date.strftime('%b %Y')
        db_month_key = target_date.strftime('%Y-%m')
        monthly_expenses_labels.append(month_label)
        expenses_by_month[db_month_key] = 0

    six_months_ago = (today - relativedelta(months=5)).replace(day=1)
    
    # --- এই কোয়েরিটি পরিবর্তন করা হয়েছে ---
    # PostgreSQL-এর জন্য func.to_char এবং SQLite-এর জন্য func.strftime ব্যবহার করা
    db_engine_name = db.engine.name
    if db_engine_name == 'postgresql':
        month_year_func = func.to_char(ConveyanceBill.bill_date, 'YYYY-MM')
    else: # Fallback to SQLite
        month_year_func = func.strftime('%Y-%m', ConveyanceBill.bill_date)
        
    conveyance_expenses_query = db.session.query(
        month_year_func.label('month_year'),
        func.sum(ConveyanceBill.amount).label('total_amount')
    ).filter(ConveyanceBill.bill_date >= six_months_ago).group_by('month_year').all()

    for expense_entry in conveyance_expenses_query:
        if expense_entry.month_year in expenses_by_month:
            expenses_by_month[expense_entry.month_year] = float(expense_entry.total_amount) # Ensure float
    
    monthly_expenses_values = [expenses_by_month[key] for key in sorted(expenses_by_month.keys())]

    # --- Recent Transactions ---
    recent_transactions = db.session.query(Transaction, Client.name.label('client_name'))\
        .join(Client, Client.id == Transaction.client_id)\
        .order_by(Transaction.transaction_date.desc(), Transaction.id.desc())\
        .limit(5).all()
    recent_transactions_list = [{'id': trx.id, 'transaction_date': trx.transaction_date, 'client_id': trx.client_id, 'client_name': name, 'narration': trx.narration, 'debit': trx.debit, 'credit': trx.credit} for trx, name in recent_transactions]
    
    # --- Conveyance Expenses for current month display card ---
    current_month_start = today.replace(day=1)
    current_month_conveyance_total = db.session.query(func.sum(ConveyanceBill.amount))\
        .filter(ConveyanceBill.bill_date >= current_month_start).scalar() or 0.0
    
    # --- Recent Conveyance Bills ---
    recent_conveyance_bills = ConveyanceBill.query.order_by(ConveyanceBill.bill_date.desc(), ConveyanceBill.id.desc()).limit(5).all()

    return render_template('index.html',
                           clients=clients_with_balances,
                           total_receivables=total_receivables,
                           recent_transactions=recent_transactions_list,
                           current_month_conveyance_total=current_month_conveyance_total,
                           recent_conveyance_bills=recent_conveyance_bills,
                           current_month_display=datetime.now().strftime("%B %Y"),
                           top_clients_labels=top_clients_labels,
                           top_clients_values=top_clients_values,
                           monthly_expenses_labels=monthly_expenses_labels,
                           monthly_expenses_values=monthly_expenses_values)


# --- Client Management Routes ---
@app.route('/add_client', methods=['GET', 'POST'])
@login_required
def add_client():
    if request.method == 'POST':
        name = request.form.get('name')
        contact_number = request.form.get('contact_number')
        
        if not name:
            flash('Client name is required!', 'error')
        else:
            existing_client = Client.query.filter_by(name=name).first()
            if existing_client:
                flash(f'Client with the name "{name}" already exists.', 'error')
            else:
                new_client = Client(name=name, contact_number=contact_number)
                db.session.add(new_client)
                db.session.commit()
                flash(f'Client "{name}" added successfully!', 'success')
                return redirect(url_for('index'))
    return render_template('add_client.html')


@app.route('/client/<int:client_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_client(client_id):
    client = db.session.get(Client, client_id)
    if not client:
        flash('Client not found.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form.get('name')
        contact_number = request.form.get('contact_number')
        
        # Check if new name is taken by another client
        existing = Client.query.filter(Client.name == name, Client.id != client_id).first()
        if existing:
            flash(f'Another client with the name "{name}" already exists.', 'error')
        else:
            client.name = name
            client.contact_number = contact_number
            db.session.commit()
            flash('Client details updated successfully!', 'success')
            return redirect(url_for('index'))
            
    return render_template('edit_client.html', client=client)


@app.route('/client/<int:client_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_client(client_id):
    client = db.session.get(Client, client_id)
    if not client:
        flash('Client not found.', 'error')
    elif client.transactions: # SQLAlchemy relationship makes this check easy
        flash(f'Cannot delete client "{client.name}" as they have existing transactions.', 'error')
    else:
        db.session.delete(client)
        db.session.commit()
        flash(f'Client "{client.name}" deleted successfully.', 'success')
    return redirect(url_for('index'))


# --- Transaction Management Routes ---
@app.route('/client/<int:client_id>/add_transaction', methods=['GET', 'POST'])
@login_required
def add_transaction(client_id):
    client = db.session.get(Client, client_id)
    if not client:
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            transaction_date = datetime.strptime(request.form.get('transaction_date'), '%Y-%m-%d').date()
            new_transaction = Transaction(
                client_id=client_id,
                transaction_date=transaction_date,
                fabrics_type=request.form.get('fabrics_type'),
                design_code=request.form.get('design_code'),
                qty=float(request.form.get('qty')) if request.form.get('qty') else None,
                transaction_mode=request.form.get('transaction_mode'),
                narration=request.form.get('narration'),
                chq_no=request.form.get('chq_no'),
                challan_voucher_no=request.form.get('challan_voucher_no'),
                debit=float(request.form.get('debit', 0)),
                credit=float(request.form.get('credit', 0))
            )
            db.session.add(new_transaction)
            db.session.commit()
            flash('Transaction added successfully!', 'success')
            return redirect(url_for('client_ledger', client_id=client_id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding transaction: {e}', 'error')

    return render_template('add_transaction.html', client=client, default_date=datetime.now().strftime('%Y-%m-%d'))


@app.route('/client/<int:client_id>/ledger')
@login_required
def client_ledger(client_id):
    client = db.session.get(Client, client_id)
    if not client:
        return redirect(url_for('index'))

    start_date_filter = request.args.get('start_date', '')
    end_date_filter = request.args.get('end_date', '')
    
    # Base query for transactions
    transactions_query = db.session.query(Transaction).filter_by(client_id=client_id)

    # Date filtering
    if start_date_filter:
        transactions_query = transactions_query.filter(Transaction.transaction_date >= start_date_filter)
    if end_date_filter:
        transactions_query = transactions_query.filter(Transaction.transaction_date <= end_date_filter)

    transactions = transactions_query.order_by(Transaction.transaction_date, Transaction.id).all()
    
    # Opening Balance Calculation
    opening_balance = 0.0
    if start_date_filter:
        ob_result = db.session.query(
            func.sum(Transaction.debit - Transaction.credit)
        ).filter(
            Transaction.client_id == client_id,
            Transaction.transaction_date < start_date_filter
        ).scalar()
        if ob_result:
            opening_balance = float(ob_result)

    # Process transactions to add running balance
    running_balance = opening_balance
    transactions_with_balance = []
    for trx in transactions:
        running_balance += (trx.debit or 0) - (trx.credit or 0)
        trx.running_balance = running_balance # Add a new attribute to the object
        transactions_with_balance.append(trx)

    total_debit = sum(t.debit for t in transactions_with_balance)
    total_credit = sum(t.credit for t in transactions_with_balance)
    closing_balance = running_balance

    return render_template('client_ledger.html',
                           client=client,
                           transactions=transactions_with_balance,
                           opening_balance=opening_balance,
                           total_debit=total_debit,
                           total_credit=total_credit,
                           closing_balance=closing_balance,
                           start_date=start_date_filter,
                           end_date=end_date_filter if end_date_filter else datetime.now().strftime('%Y-%m-%d'))


@app.route('/transaction/<int:transaction_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_transaction(transaction_id):
    trx = db.session.get(Transaction, transaction_id)
    if not trx:
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            trx.transaction_date = datetime.strptime(request.form.get('transaction_date'), '%Y-%m-%d').date()
            trx.fabrics_type = request.form.get('fabrics_type')
            # ... update all other fields ...
            trx.debit = float(request.form.get('debit', 0))
            trx.credit = float(request.form.get('credit', 0))
            db.session.commit()
            flash('Transaction updated successfully!', 'success')
            return redirect(url_for('client_ledger', client_id=trx.client_id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating transaction: {e}', 'error')

    return render_template('edit_transaction.html', transaction=trx, client=trx.client)


@app.route('/transaction/<int:transaction_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_transaction(transaction_id):
    trx = db.session.get(Transaction, transaction_id)
    if trx:
        client_id_for_redirect = trx.client_id
        db.session.delete(trx)
        db.session.commit()
        flash('Transaction deleted.', 'success')
        return redirect(url_for('client_ledger', client_id=client_id_for_redirect))
    return redirect(url_for('index'))

# --- Report Routes ---
@app.route('/reports/monthly_client_summary', methods=['GET'])
@login_required
def monthly_client_summary_report():
    filter_year, filter_month = request.args.get('filter_year', ''), request.args.get('filter_month', '')
    
    db_engine_name = db.engine.name
    if db_engine_name == 'postgresql':
        year_func = extract('year', Transaction.transaction_date)
        month_func = extract('month', Transaction.transaction_date)
    else: # SQLite
        year_func = func.strftime('%Y', Transaction.transaction_date)
        month_func = func.strftime('%m', Transaction.transaction_date)

    query = db.session.query(
        Client.id.label('client_id'), Client.name.label('client_name'),
        year_func.label('year'),
        month_func.label('month'),
        func.sum(Transaction.debit).label('total_debit'),
        func.sum(Transaction.credit).label('total_credit'),
        (func.coalesce(func.sum(Transaction.debit), 0) - func.coalesce(func.sum(Transaction.credit), 0)).label('net_change')
    ).join(Client)

    if filter_year: query = query.filter(year_func == int(filter_year))
    if filter_month: query = query.filter(month_func == int(filter_month))
    
    summary_data = query.group_by(Client.id, 'year', 'month').order_by(db.desc('year'), db.desc('month'), Client.name).all()

    distinct_years_rows = db.session.query(extract('year', Transaction.transaction_date).label('year')).distinct().order_by(db.desc('year')).all()
    distinct_years = [row.year for row in distinct_years_rows]
    
    month_map = {
        1: "January", 2: "February", 3: "March", 4: "April", 5: "May", 6: "June",
        7: "July", 8: "August", 9: "September", 10: "October", 11: "November", 12: "December"
    }
    
    grand_total_debit = sum(item.total_debit for item in summary_data if item.total_debit)
    grand_total_credit = sum(item.total_credit for item in summary_data if item.total_credit)
    grand_total_net_change = sum(item.net_change for item in summary_data if item.net_change)

    return render_template('report_monthly_client_summary.html',
                           summary_data=summary_data,
                           distinct_years=distinct_years,
                           month_map=month_map,
                           filter_year=filter_year,
                           filter_month=filter_month,
                           grand_total_debit=grand_total_debit,
                           grand_total_credit=grand_total_credit,
                           grand_total_net_change=grand_total_net_change)

# --- Conveyance Bill Routes ---
@app.route('/conveyance_bills')
@login_required
def view_conveyance_bills():
    query = ConveyanceBill.query
    filter_date_from = request.args.get('filter_date_from', '')
    filter_date_to = request.args.get('filter_date_to', '')
    filter_person_name = request.args.get('filter_person_name', '')

    if filter_date_from:
        query = query.filter(ConveyanceBill.bill_date >= filter_date_from)
    if filter_date_to:
        query = query.filter(ConveyanceBill.bill_date <= filter_date_to)
    if filter_person_name:
        query = query.filter(ConveyanceBill.person_name.ilike(f"%{filter_person_name}%"))

    bills = query.order_by(ConveyanceBill.bill_date.desc(), ConveyanceBill.id.desc()).all()
    total_amount = sum(bill.amount for bill in bills)
    
    distinct_persons_rows = db.session.query(ConveyanceBill.person_name).distinct().order_by(ConveyanceBill.person_name).all()
    distinct_persons = [row[0] for row in distinct_persons_rows]

    return render_template('view_conveyance_bills.html',
                           bills=bills, total_amount=total_amount,
                           filter_date_from=filter_date_from, filter_date_to=filter_date_to,
                           filter_person_name=filter_person_name, distinct_persons=distinct_persons)

@app.route('/add_conveyance', methods=['GET', 'POST'])
@login_required
def add_conveyance():
    if request.method == 'POST':
        try:
            new_bill = ConveyanceBill(
                bill_date=datetime.strptime(request.form.get('bill_date'), '%Y-%m-%d').date(),
                person_name=request.form.get('person_name'),
                from_location=request.form.get('from_location'),
                to_location=request.form.get('to_location'),
                purpose=request.form.get('purpose'),
                amount=float(request.form.get('amount'))
            )
            db.session.add(new_bill)
            db.session.commit()
            flash('Conveyance bill added successfully!', 'success')
            return redirect(url_for('view_conveyance_bills'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding conveyance bill: {e}', 'error')
    
    return render_template('add_conveyance.html', default_date=datetime.now().strftime('%Y-%m-%d'))

@app.route('/conveyance/<int:bill_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_conveyance_bill(bill_id):
    bill = db.session.get(ConveyanceBill, bill_id)
    if not bill:
        return redirect(url_for('view_conveyance_bills'))

    if request.method == 'POST':
        try:
            bill.bill_date = datetime.strptime(request.form.get('bill_date'), '%Y-%m-%d').date()
            bill.person_name = request.form.get('person_name')
            bill.from_location = request.form.get('from_location')
            bill.to_location = request.form.get('to_location')
            bill.purpose = request.form.get('purpose')
            bill.amount = float(request.form.get('amount'))
            db.session.commit()
            flash('Conveyance bill updated!', 'success')
            return redirect(url_for('view_conveyance_bills'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating bill: {e}', 'error')
            
    return render_template('edit_conveyance_bill.html', bill=bill)

@app.route('/conveyance/<int:bill_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_conveyance_bill(bill_id):
    bill = db.session.get(ConveyanceBill, bill_id)
    if bill:
        db.session.delete(bill)
        db.session.commit()
        flash('Conveyance bill deleted.', 'success')
    return redirect(url_for('view_conveyance_bills'))

# --- Production Routes ---

@app.route('/production/daily_report', methods=['GET', 'POST'])
@login_required
def daily_production_report():
    if request.method == 'POST':
        try:
            new_entry = DailyProduction(
                production_date=datetime.strptime(request.form.get('production_date'), '%Y-%m-%d').date(),
                machine_number=request.form.get('machine_number'),
                design_number=request.form.get('design_number'),
                client_name=request.form.get('client_name'),
                total_production=float(request.form.get('total_production')),
                production_unit=request.form.get('production_unit')
            )
            db.session.add(new_entry)
            db.session.commit()
            flash('Production entry added successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding production entry: {e}', 'error')
        return redirect(url_for('daily_production_report'))

    # Filtering logic for GET request
    query = DailyProduction.query
    filter_specific_date = request.args.get('filter_specific_date', '')
    filter_client_name = request.args.get('filter_client_name', '')
    filter_year = request.args.get('filter_year', '')

    if filter_specific_date:
        query = query.filter(DailyProduction.production_date == filter_specific_date)
    elif filter_year:
        query = query.filter(extract('year', DailyProduction.production_date) == int(filter_year))
        
    if filter_client_name:
        query = query.filter(DailyProduction.client_name.ilike(f"%{filter_client_name}%"))

    production_entries = query.order_by(DailyProduction.production_date.desc(), DailyProduction.id.desc()).all()

    # Data for filters
    distinct_years_rows = db.session.query(extract('year', DailyProduction.production_date).label('year')).distinct().order_by(db.desc('year')).all()
    distinct_clients_rows = db.session.query(DailyProduction.client_name).filter(DailyProduction.client_name.isnot(None)).distinct().order_by(DailyProduction.client_name).all()
    
    distinct_years_for_filter = [row.year for row in distinct_years_rows]
    distinct_clients_for_filter = [row.client_name for row in distinct_clients_rows]
    
    return render_template('production/daily_production_report.html',
                           production_entries=production_entries,
                           form_data={}, # Form data is handled by POST logic
                           default_date_form=datetime.now().strftime('%Y-%m-%d'),
                           distinct_years_for_filter=distinct_years_for_filter,
                           distinct_clients_for_filter=distinct_clients_for_filter,
                           filter_specific_date=filter_specific_date,
                           filter_client_name=filter_client_name,
                           filter_year=filter_year)


@app.route('/production/<int:entry_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_production_entry(entry_id):
    entry = db.session.get(DailyProduction, entry_id)
    if not entry:
        return redirect(url_for('daily_production_report'))

    if request.method == 'POST':
        try:
            entry.production_date = datetime.strptime(request.form.get('production_date'), '%Y-%m-%d').date()
            entry.machine_number = request.form.get('machine_number')
            entry.design_number = request.form.get('design_number')
            entry.client_name = request.form.get('client_name')
            entry.total_production = float(request.form.get('total_production'))
            entry.production_unit = request.form.get('production_unit')
            db.session.commit()
            flash('Production entry updated successfully!', 'success')
            return redirect(url_for('daily_production_report'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating entry: {e}', 'error')
            
    return render_template('production/edit_production_entry.html', entry=entry)


@app.route('/production/<int:entry_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_production_entry(entry_id):
    entry = db.session.get(DailyProduction, entry_id)
    if entry:
        db.session.delete(entry)
        db.session.commit()
        flash('Production entry deleted.', 'success')
    return redirect(url_for('daily_production_report'))

# app.py - Part 5: Inventory, Admin, and Export Routes

def allowed_image_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

def allowed_csv_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_CSV_EXTENSIONS


# --- Admin Routes (User and Company Management) ---
@app.route('/edit_company_details', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_company_details():
    company_info = db.session.get(CompanyDetails, 1)
    if not company_info:
        # If no company details exist, create one
        company_info = CompanyDetails(id=1, company_name="Your Company")
        db.session.add(company_info)
        db.session.commit()

    if request.method == 'POST':
        try:
            company_info.company_name = request.form.get('company_name')
            company_info.address = request.form.get('address')
            company_info.contact_info = request.form.get('contact_info')
            
            # Handle Monogram File Upload
            if 'monogram_file' in request.files:
                file = request.files['monogram_file']
                if file and file.filename != '':
                    if allowed_image_file(file.filename):
                        filename = secure_filename(file.filename)
                        # Optional: delete old file logic here
                        file.save(os.path.join(MONOGRAM_UPLOAD_FOLDER, filename))
                        company_info.monogram_path = filename # Store just the filename
                    else:
                        flash('Invalid image file type.', 'error')

            db.session.commit()
            flash('Company details updated successfully!', 'success')
            return redirect(url_for('edit_company_details'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating company details: {e}', 'error')

    return render_template('edit_company_details.html', company_info=company_info)

@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    users = User.query.order_by(User.username).all()
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user_admin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = True if request.form.get('is_admin') else False
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'error')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_password, is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()
            flash(f'User "{username}" created successfully.', 'success')
            return redirect(url_for('manage_users'))
            
    return render_template('admin/add_user.html')

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user_admin(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        new_username = request.form.get('username').strip()
        new_is_admin = True if request.form.get('is_admin') else False
        new_password = request.form.get('password')

        existing = User.query.filter(User.username == new_username, User.id != user_id).first()
        if existing:
            flash(f'Username "{new_username}" is already taken.', 'error')
        else:
            user.username = new_username
            user.is_admin = new_is_admin
            if new_password:
                user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash('User details updated.', 'success')
            return redirect(url_for('manage_users'))
            
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user_admin(user_id):
    if user_id == current_user.id:
        flash("You cannot delete yourself.", "error")
        return redirect(url_for('manage_users'))
    if user_id == 1:
        flash("The primary administrator cannot be deleted. (কাজটা তুমি ঠিক করলে না মাসুদ!)", "error")
        return redirect(url_for('manage_users'))
        
    user = db.session.get(User, user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f"User '{user.username}' has been deleted.", "success")
    return redirect(url_for('manage_users'))

# --- Inventory Item Management Routes ---
@app.route('/admin/inventory_items', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_inventory_items():
    if request.method == 'POST':
        try:
            new_item = InventoryItem(
                product_type=request.form.get('product_type'),
                sub_type=request.form.get('sub_type').strip(),
                default_unit=request.form.get('default_unit'),
                description=request.form.get('description').strip()
            )
            db.session.add(new_item)
            db.session.commit()
            flash(f'Inventory item "{new_item.product_type} - {new_item.sub_type}" added.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: Could not add item. It might already exist. ({e})', 'error')
        return redirect(url_for('manage_inventory_items'))

    items = InventoryItem.query.order_by(InventoryItem.product_type, InventoryItem.sub_type).all()
    product_type_options = ['Fabric', 'Paper', 'Color', 'Chemical', 'Other']
    unit_options = ['yards', 'meters', 'kg', 'grams', 'liters', 'ml', 'sheets', 'pcs', 'rolls', 'Other']
    return render_template('admin/manage_inventory_items.html', items=items, product_type_options=product_type_options, unit_options=unit_options, form_data={})

@app.route('/admin/inventory_items/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_inventory_item(item_id):
    item = db.session.get(InventoryItem, item_id)
    if not item:
        return redirect(url_for('manage_inventory_items'))

    if request.method == 'POST':
        try:
            item.product_type = request.form.get('product_type')
            item.sub_type = request.form.get('sub_type').strip()
            item.default_unit = request.form.get('default_unit')
            item.description = request.form.get('description').strip()
            db.session.commit()
            flash('Item definition updated.', 'success')
            return redirect(url_for('manage_inventory_items'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating item: {e}', 'error')
            
    product_type_options = ['Fabric', 'Paper', 'Color', 'Chemical', 'Other']
    unit_options = ['yards', 'meters', 'kg', 'grams', 'liters', 'ml', 'sheets', 'pcs', 'rolls', 'Other']
    return render_template('admin/edit_inventory_item.html', item=item, product_type_options=product_type_options, unit_options=unit_options)

@app.route('/admin/inventory_items/<int:item_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_inventory_item(item_id):
    item = db.session.get(InventoryItem, item_id)
    if item:
        if item.transactions.first():
            flash('Cannot delete item as it has existing transactions.', 'error')
        else:
            db.session.delete(item)
            db.session.commit()
            flash(f'Item "{item.product_type} - {item.sub_type}" deleted.', 'success')
    return redirect(url_for('manage_inventory_items'))

# --- Inventory Transaction Routes (IN/OUT Forms) ---
@app.route('/inventory/in', methods=['GET', 'POST'])
@login_required
def inventory_in_form():
    if request.method == 'POST':
        try:
            item_id = int(request.form.get('inventory_item_id'))
            item_def = db.session.get(InventoryItem, item_id)
            if not item_def:
                raise ValueError("Selected item not found.")
            
            new_trx = InventoryTransaction(
                transaction_date=datetime.strptime(request.form.get('transaction_date'), '%Y-%m-%d').date(),
                transaction_type='IN',
                inventory_item_id=item_id,
                product_type=item_def.product_type,
                sub_type=item_def.sub_type,
                quantity=float(request.form.get('quantity')),
                unit=request.form.get('unit'),
                total_price=float(request.form.get('total_price')) if request.form.get('total_price') else None,
                client_name=request.form.get('client_name'),
                remarks=request.form.get('remarks'),
                user_id=current_user.id
            )
            db.session.add(new_trx)
            db.session.commit()
            flash('Stock IN recorded successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error recording stock IN: {e}', 'error')
        return redirect(url_for('inventory_in_form'))

    inventory_item_options = InventoryItem.query.order_by(InventoryItem.product_type, InventoryItem.sub_type).all()
    unit_options = ['yards', 'meters', 'kg', 'grams', 'liters', 'ml', 'sheets', 'pcs', 'rolls', 'Other']
    return render_template('inventory/stock_in_form.html', inventory_item_options=inventory_item_options, unit_options=unit_options, default_date_form=datetime.now().strftime('%Y-%m-%d'))


@app.route('/inventory/out', methods=['GET', 'POST'])
@login_required
def inventory_out_form():
    if request.method == 'POST':
        try:
            item_id = int(request.form.get('inventory_item_id'))
            quantity_to_issue = float(request.form.get('quantity'))

            # Stock check
            stock_data = db.session.query(
                func.sum(case((InventoryTransaction.transaction_type == 'IN', InventoryTransaction.quantity), else_=-InventoryTransaction.quantity))
            ).filter(InventoryTransaction.inventory_item_id == item_id).scalar()
            available_stock = stock_data or 0.0
            
            if quantity_to_issue > available_stock:
                item_def = db.session.get(InventoryItem, item_id)
                flash(f'Insufficient stock for "{item_def.sub_type}". Available: {available_stock:.2f}', 'error')
            else:
                item_def = db.session.get(InventoryItem, item_id)
                new_trx = InventoryTransaction(
                    transaction_date=datetime.strptime(request.form.get('transaction_date'), '%Y-%m-%d').date(),
                    transaction_type='OUT',
                    inventory_item_id=item_id,
                    product_type=item_def.product_type,
                    sub_type=item_def.sub_type,
                    quantity=quantity_to_issue,
                    unit=request.form.get('unit'),
                    total_price=float(request.form.get('total_price')) if request.form.get('total_price') else None,
                    client_name=request.form.get('client_name'),
                    remarks=request.form.get('remarks'),
                    user_id=current_user.id
                )
                db.session.add(new_trx)
                db.session.commit()
                flash('Stock OUT recorded successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error recording stock OUT: {e}', 'error')
        return redirect(url_for('inventory_out_form'))

    inventory_item_options = InventoryItem.query.order_by(InventoryItem.product_type, InventoryItem.sub_type).all()
    unit_options = ['yards', 'meters', 'kg', 'grams', 'liters', 'ml', 'sheets', 'pcs', 'rolls', 'Other']
    return render_template('inventory/stock_out_form.html', inventory_item_options=inventory_item_options, unit_options=unit_options, default_date_form=datetime.now().strftime('%Y-%m-%d'))


@app.route('/inventory/transactions')
@login_required
def inventory_transactions_list():
    query = db.session.query(InventoryTransaction)
    
    # Filters
    filter_date_from = request.args.get('filter_date_from', '')
    filter_date_to = request.args.get('filter_date_to', '')
    filter_transaction_type = request.args.get('filter_transaction_type', '')
    filter_product_type = request.args.get('filter_product_type', '')
    filter_sub_type = request.args.get('filter_sub_type', '')
    filter_client_name = request.args.get('filter_client_name', '')

    if filter_date_from:
        query = query.filter(InventoryTransaction.transaction_date >= filter_date_from)
    if filter_date_to:
        query = query.filter(InventoryTransaction.transaction_date <= filter_date_to)
    if filter_transaction_type:
        query = query.filter(InventoryTransaction.transaction_type == filter_transaction_type)
    if filter_product_type:
        query = query.filter(InventoryTransaction.product_type == filter_product_type)
    if filter_sub_type:
        query = query.filter(InventoryTransaction.sub_type.ilike(f"%{filter_sub_type}%"))
    if filter_client_name:
        query = query.filter(InventoryTransaction.client_name.ilike(f"%{filter_client_name}%"))

    transactions = query.order_by(InventoryTransaction.transaction_date.desc(), InventoryTransaction.id.desc()).all()

    product_type_options_rows = db.session.query(InventoryItem.product_type).distinct().order_by(InventoryItem.product_type).all()
    product_type_options_list = [row.product_type for row in product_type_options_rows]

    return render_template('inventory/transactions_list.html',
                           transactions=transactions,
                           filter_date_from=filter_date_from,
                           filter_date_to=filter_date_to,
                           filter_transaction_type=filter_transaction_type,
                           filter_product_type=filter_product_type,
                           product_type_options=product_type_options_list,
                           filter_sub_type=filter_sub_type,
                           filter_client_name=filter_client_name)


@app.route('/inventory/dashboard', methods=['GET'])
@login_required
def store_dashboard():
    # Filters for summary cards and chart
    filter_date_from = request.args.get('filter_date_from', '')
    filter_date_to = request.args.get('filter_date_to', '')
    filter_summary_product_type = request.args.get('filter_summary_product_type', '')

    # 1. Current Stock (Always overall)
    current_stock_query = db.session.query(
        InventoryItem.id.label('item_id'),
        InventoryItem.product_type,
        InventoryItem.sub_type,
        InventoryItem.default_unit,
        func.coalesce(func.sum(
            case((InventoryTransaction.transaction_type == 'IN', InventoryTransaction.quantity),
                 else_=-InventoryTransaction.quantity)
        ), 0).label('current_quantity')
    ).outerjoin(InventoryTransaction).group_by(InventoryItem.id).order_by(InventoryItem.product_type, InventoryItem.sub_type)
    
    current_stock_list = current_stock_query.all()
    stock_by_product_type = defaultdict(list)
    for item_stock in current_stock_list:
        stock_by_product_type[item_stock.product_type].append(item_stock)

    # 2. & 3. Filterable IN/OUT Summaries
    in_summary_query = db.session.query(
        func.count(InventoryTransaction.id),
        func.coalesce(func.sum(InventoryTransaction.quantity), 0),
        func.coalesce(func.sum(InventoryTransaction.total_price), 0)
    ).filter(InventoryTransaction.transaction_type == 'IN')

    out_summary_query = db.session.query(
        func.count(InventoryTransaction.id),
        func.coalesce(func.sum(InventoryTransaction.quantity), 0),
        func.coalesce(func.sum(InventoryTransaction.total_price), 0)
    ).filter(InventoryTransaction.transaction_type == 'OUT')

    # Apply common filters to both summary queries
    for query in [in_summary_query, out_summary_query]:
        if filter_date_from:
            query = query.filter(InventoryTransaction.transaction_date >= filter_date_from)
        if filter_date_to:
            query = query.filter(InventoryTransaction.transaction_date <= filter_date_to)
        if filter_summary_product_type:
            query = query.filter(InventoryTransaction.product_type == filter_summary_product_type)
    
    in_trx_count, in_qty, in_val = in_summary_query.first()
    out_trx_count, out_qty, out_val = out_summary_query.first()

    total_in_summary = {'total_in_transactions': in_trx_count, 'total_quantity_received': in_qty, 'total_value_spent': in_val}
    total_out_summary = {'total_out_transactions': out_trx_count, 'total_quantity_issued': out_qty, 'total_value_issued': out_val}

    # 4. Chart Data
    chart_query = db.session.query(
        InventoryTransaction.product_type,
        func.sum(case((InventoryTransaction.transaction_type == 'IN', InventoryTransaction.quantity), else_=0)).label('total_in_qty'),
        func.sum(case((InventoryTransaction.transaction_type == 'OUT', InventoryTransaction.quantity), else_=0)).label('total_out_qty')
    )
    if filter_date_from: chart_query = chart_query.filter(InventoryTransaction.transaction_date >= filter_date_from)
    if filter_date_to: chart_query = chart_query.filter(InventoryTransaction.transaction_date <= filter_date_to)
    if filter_summary_product_type: chart_query = chart_query.filter(InventoryTransaction.product_type == filter_summary_product_type)

    in_out_chart_data_rows = chart_query.group_by(InventoryTransaction.product_type).order_by(InventoryTransaction.product_type).all()
    
    chart_labels = [row.product_type for row in in_out_chart_data_rows]
    chart_in_values = [row.total_in_qty for row in in_out_chart_data_rows]
    chart_out_values = [row.total_out_qty for row in in_out_chart_data_rows]

    # For filter dropdown
    product_type_filter_options_rows = db.session.query(InventoryItem.product_type).distinct().order_by(InventoryItem.product_type).all()
    product_type_filter_options_list = [row.product_type for row in product_type_filter_options_rows]

    return render_template('inventory/store_dashboard.html',
                           stock_by_product_type=stock_by_product_type,
                           total_in_summary=total_in_summary,
                           total_out_summary=total_out_summary,
                           filter_date_from=filter_date_from, filter_date_to=filter_date_to,
                           filter_summary_product_type=filter_summary_product_type,
                           product_type_filter_options=product_type_filter_options_list,
                           chart_labels=chart_labels, chart_in_values=chart_in_values, chart_out_values=chart_out_values)


# --- CSV & PDF Export Routes ---

@app.route('/export/clients_csv')
@login_required
def export_clients_csv():
    # This query joins Client and Transaction tables to calculate balance for each client
    clients_with_balances = db.session.query(
        Client.id, Client.name, Client.contact_number,
        (func.coalesce(func.sum(Transaction.debit), 0) - func.coalesce(func.sum(Transaction.credit), 0)).label('balance')
    ).outerjoin(Transaction, Client.id == Transaction.client_id).group_by(Client.id).order_by(Client.name).all()
    
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Client ID', 'Client Name', 'Contact Number', 'Balance'])
    for client in clients_with_balances:
        cw.writerow([client.id, client.name, client.contact_number, f"{client.balance:.2f}"])
        
    output = si.getvalue()
    si.close()
    return Response(output, mimetype="text/csv", headers={"Content-disposition": "attachment; filename=clients_report.csv"})

# app.py - Part 7: Finalizing Export and Import Routes

# --- Export Routes (Continued) ---

@app.route('/export/client_ledger_csv/<int:client_id>')
@login_required
def export_client_ledger_csv(client_id):
    client = db.session.get(Client, client_id)
    if not client:
        flash('Client not found.', 'error')
        return redirect(url_for('index'))

    start_date_filter = request.args.get('start_date', '')
    end_date_filter = request.args.get('end_date', '')

    # Base query
    transactions_query = db.session.query(Transaction).filter_by(client_id=client_id)
    if start_date_filter:
        transactions_query = transactions_query.filter(Transaction.transaction_date >= start_date_filter)
    if end_date_filter:
        transactions_query = transactions_query.filter(Transaction.transaction_date <= end_date_filter)
    transactions = transactions_query.order_by(Transaction.transaction_date, Transaction.id).all()

    # Opening Balance
    opening_balance = 0.0
    if start_date_filter:
        ob_result = db.session.query(
            func.sum(Transaction.debit - Transaction.credit)
        ).filter(Transaction.client_id == client_id, Transaction.transaction_date < start_date_filter).scalar()
        if ob_result: opening_balance = float(ob_result)

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Client Name:', client.name])
    cw.writerow(['Contact:', client.contact_number or 'N/A'])
    cw.writerow(['Period:', f"{start_date_filter or 'Beginning'} to {end_date_filter or 'Current'}"])
    cw.writerow([])
    cw.writerow(['Date', 'Fabrics Type', 'Design Code', 'Qty', 'Transaction Mode', 'Narration', 'Chq No.', 'Voucher No.', 'Debit', 'Credit', 'Balance'])
    
    if start_date_filter:
        ob_row = [''] * 11
        ob_row[0] = 'Opening Balance'
        ob_row[-1] = f"{opening_balance:.2f}"
        cw.writerow(ob_row)

    running_balance = opening_balance
    for trx in transactions:
        running_balance += (trx.debit or 0) - (trx.credit or 0)
        cw.writerow([
            trx.transaction_date.strftime('%Y-%m-%d'), trx.fabrics_type, trx.design_code, trx.qty,
            trx.transaction_mode, trx.narration, trx.chq_no, trx.challan_voucher_no,
            f"{trx.debit:.2f}", f"{trx.credit:.2f}", f"{running_balance:.2f}"
        ])

    output = si.getvalue()
    si.close()
    filename = f"ledger_{client.name.replace(' ', '_')}_{start_date_filter}_to_{end_date_filter}.csv"
    return Response(output, mimetype="text/csv", headers={"Content-disposition": f"attachment; filename={filename}"})


@app.route('/export/conveyance_bills_csv')
@login_required
def export_conveyance_bills_csv():
    query = ConveyanceBill.query
    filter_date_from = request.args.get('filter_date_from', '')
    filter_date_to = request.args.get('filter_date_to', '')
    filter_person_name = request.args.get('filter_person_name', '')

    if filter_date_from: query = query.filter(ConveyanceBill.bill_date >= filter_date_from)
    if filter_date_to: query = query.filter(ConveyanceBill.bill_date <= filter_date_to)
    if filter_person_name: query = query.filter(ConveyanceBill.person_name.ilike(f"%{filter_person_name}%"))

    bills = query.order_by(ConveyanceBill.bill_date.desc(), ConveyanceBill.id.desc()).all()
    
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Bill ID', 'Date', 'Person Name', 'From Location', 'To Location', 'Purpose', 'Amount'])
    
    total_amount = 0
    for bill in bills:
        cw.writerow([
            bill.id, bill.bill_date.strftime('%Y-%m-%d'), bill.person_name,
            bill.from_location, bill.to_location, bill.purpose, f"{bill.amount:.2f}"
        ])
        total_amount += bill.amount

    cw.writerow([])
    total_row = [''] * 6
    total_row[-1] = "Total Amount:"
    total_row.append(f"{total_amount:.2f}")
    cw.writerow(total_row)
    
    output = si.getvalue()
    si.close()
    filename = f"conveyance_bills_export.csv"
    return Response(output, mimetype="text/csv", headers={"Content-disposition": f"attachment; filename={filename}"})

@app.route('/export/production_pdf')
@login_required
def export_production_pdf():
    # PDF generation is complex and not yet implemented.
    flash('PDF export for production reports is not yet implemented.', 'info')
    # Redirect back to the report page, preserving filters
    return redirect(url_for('daily_production_report', **request.args))

@app.route('/export/production_csv')
@login_required
def export_production_csv():
    query = DailyProduction.query
    filter_specific_date = request.args.get('filter_specific_date', '')
    filter_client_name = request.args.get('filter_client_name', '')
    filter_year = request.args.get('filter_year', '')

    if filter_specific_date: query = query.filter(DailyProduction.production_date == filter_specific_date)
    elif filter_year: query = query.filter(extract('year', DailyProduction.production_date) == int(filter_year))
    if filter_client_name: query = query.filter(DailyProduction.client_name.ilike(f"%{filter_client_name}%"))

    entries = query.order_by(DailyProduction.production_date.desc(), DailyProduction.id.desc()).all()
    
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Date', 'Machine No.', 'Design No.', 'Client Name', 'Total Production', 'Unit'])
    for entry in entries:
        cw.writerow([
            entry.id, entry.production_date.strftime('%Y-%m-%d'), entry.machine_number, entry.design_number,
            entry.client_name, entry.total_production, entry.production_unit
        ])
        
    output = si.getvalue()
    si.close()
    filename = f"production_report_export.csv"
    return Response(output, mimetype="text/csv", headers={"Content-disposition": f"attachment; filename={filename}"})


# --- CSV Transaction Import Route ---
@app.route('/import/transactions_csv', methods=['GET', 'POST'])
@login_required
@admin_required
def import_transactions_csv():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if file and allowed_csv_file(file.filename): # Assuming allowed_csv_file is defined
            filename = secure_filename(file.filename)
            filepath = os.path.join(TRANSACTION_UPLOAD_FOLDER, filename)
            file.save(filepath)

            try:
                df = pd.read_csv(filepath)
                required_columns = ['Client Name', 'Date', 'Transaction Mode', 'Debit', 'Credit']
                actual_columns = [col.strip() for col in df.columns]
                df.columns = actual_columns

                missing_cols = [col for col in required_columns if col not in df.columns]
                if missing_cols:
                    flash(f'CSV is missing required columns: {", ".join(missing_cols)}', 'error')
                    os.remove(filepath)
                    return redirect(request.url)

                imported_count = 0
                skipped_rows = []
                
                # Fetch all client names into a dictionary for faster lookup
                clients_map = {client.name: client.id for client in Client.query.all()}

                for index, row in df.iterrows():
                    client_name = str(row.get('Client Name', '')).strip()
                    # Find client_id from our map
                    client_id = clients_map.get(client_name)

                    if not client_id:
                        skipped_rows.append({'row_num': index + 2, 'reason': f'Client "{client_name}" not found in database.'})
                        continue

                    try:
                        new_transaction = Transaction(
                            client_id=client_id,
                            transaction_date=datetime.strptime(str(row.get('Date')).strip(), '%Y-%m-%d').date(),
                            fabrics_type=str(row.get('Fabrics Type', '')).strip(),
                            design_code=str(row.get('Design Code', '')).strip(),
                            qty=float(row.get('Qty')) if pd.notna(row.get('Qty')) else None,
                            transaction_mode=str(row.get('Transaction Mode', '')).strip(),
                            narration=str(row.get('Narration', '')).strip(),
                            chq_no=str(row.get('Chq No.', '')).strip(),
                            challan_voucher_no=str(row.get('Challan/Voucher No.', '')).strip(),
                            debit=float(row.get('Debit', 0)),
                            credit=float(row.get('Credit', 0))
                        )
                        db.session.add(new_transaction)
                        imported_count += 1
                    except Exception as e:
                        skipped_rows.append({'row_num': index + 2, 'reason': f'Data Error: {e}'})
                
                db.session.commit() # Commit all successful transactions at once
                os.remove(filepath) # Clean up file

                # Flash summary messages
                success_msg = f'{imported_count} transactions imported successfully.'
                if not skipped_rows:
                    flash(success_msg, 'success')
                else:
                    success_msg += f' {len(skipped_rows)} rows were skipped.'
                    flash(success_msg, 'warning')
                    for skipped in skipped_rows[:5]:
                         flash(f"Skipped Row {skipped['row_num']}: {skipped['reason']}", "error")
                    if len(skipped_rows) > 5:
                        flash("...and more rows skipped. Check log for details.", "warning")

                return redirect(url_for('index'))

            except Exception as e:
                db.session.rollback()
                flash(f'Error processing CSV file: {e}', 'error')
                if os.path.exists(filepath): os.remove(filepath)
                return redirect(request.url)
        else:
            flash('Invalid file type. Please upload a CSV file.', 'error')
            return redirect(request.url)

    return render_template('import_transactions.html')
@login_required
@admin_required
def allowed_csv_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_CSV_EXTENSIONS

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not db.session.get(CompanyDetails, 1):
             default_company = CompanyDetails(id=1, company_name='Trims Mart', address='Your Address', contact_info='Your Contact Info')
             db.session.add(default_company)
             db.session.commit()
    app.run(debug=True)