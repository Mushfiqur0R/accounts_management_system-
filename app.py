# app.py - Part 1: Setup, Models, and Authentication

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
if not os.path.exists(MONOGRAM_UPLOAD_FOLDER):
    os.makedirs(MONOGRAM_UPLOAD_FOLDER)

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
    ).outerjoin(Transaction, Client.id == Transaction.client_id).group_by(Client.id).order_by(db.desc('balance')).all()
    
    total_receivables = sum(client.balance for client in clients_with_balances)

    # --- Chart Data: Top 5 Clients by Balance ---
    top_clients_data = sorted([c for c in clients_with_balances if c.balance > 0], key=lambda x: x.balance, reverse=True)[:5]
    top_clients_labels = [client.name for client in top_clients_data]
    top_clients_values = [client.balance for client in top_clients_data]

    # --- Chart Data: Monthly Conveyance Expenses (Last 6 Months) ---
    today = datetime.today()
    monthly_expenses_labels = []
    monthly_expenses_values = []
    expenses_by_month = defaultdict(float)
    
    for i in range(5, -1, -1):
        target_date = today - relativedelta(months=i)
        month_label = target_date.strftime('%b %Y')
        db_month_key = target_date.strftime('%Y-%m')
        monthly_expenses_labels.append(month_label)
        expenses_by_month[db_month_key] = 0

    six_months_ago = (today - relativedelta(months=5)).replace(day=1)
    
    conveyance_expenses_query = db.session.query(
        func.strftime('%Y-%m', ConveyanceBill.bill_date).label('month_year'),
        func.sum(ConveyanceBill.amount).label('total_amount')
    ).filter(ConveyanceBill.bill_date >= six_months_ago).group_by('month_year').all()

    for expense_entry in conveyance_expenses_query:
        if expense_entry.month_year in expenses_by_month:
            expenses_by_month[expense_entry.month_year] = expense_entry.total_amount
    
    monthly_expenses_values = [expenses_by_month[key] for key in sorted(expenses_by_month.keys())]

    # --- Recent Transactions ---
    recent_transactions = db.session.query(Transaction, Client.name.label('client_name'))\
        .join(Client, Client.id == Transaction.client_id)\
        .order_by(Transaction.transaction_date.desc(), Transaction.id.desc())\
        .limit(5).all()
    
    # Process recent_transactions to be a list of dicts/objects that template expects
    recent_transactions_list = [{**trx[0].__dict__, 'client_name': trx.client_name} for trx in recent_transactions]
    
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
    # ... This route needs to be updated with a new query ...
    # Placeholder for now
    return "Monthly Client Summary report needs to be updated for SQLAlchemy."

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not db.session.get(CompanyDetails, 1):
             default_company = CompanyDetails(id=1, company_name='Trims Mart', address='Your Address', contact_info='Your Contact Info')
             db.session.add(default_company)
             db.session.commit()
    app.run(debug=True)