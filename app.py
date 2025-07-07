import sqlite3
from flask import Flask, render_template, request, redirect, url_for, g, flash, abort, Response # Added Response
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
import io # For in-memory file handling
import csv # For CSV generation
from collections import defaultdict # For grouping expenses by month
import calendar # For month names and days in month
import pandas as pd # For CSV/Excel import
from werkzeug.utils import secure_filename # For secure file uploads
import os, psycopg2 # For upload folder
from werkzeug.utils import secure_filename
from psycopg2.extras import DictCursor
from dotenv import load_dotenv

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'persistent_data')
DATABASE_PATH = os.path.join(DATA_DIR, 'database.db')
MONOGRAM_UPLOAD_FOLDER = os.path.join(DATA_DIR, 'monograms')

# Ensure directories exist when the app starts.
# Render might wipe empty directories on build, so this check on startup is good.
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)
if not os.path.exists(MONOGRAM_UPLOAD_FOLDER):
    os.makedirs(MONOGRAM_UPLOAD_FOLDER)

app = Flask(__name__)
# Make sure a strong SECRET_KEY is set here or in environment variables
app.secret_key = os.environ.get('SECRET_KEY', '20250')

# --- Database Helper Functions ---
# (This section from the previous response is correct and should remain)
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
    print("SUCCESS: Database has been initialized with all tables.")

@app.cli.command('init-db')
def init_db_command():
    init_db()

DB_INITIALIZED = False

@app.before_request
def check_database_before_request():
    global DB_INITIALIZED
    if not DB_INITIALIZED:
        print("Running first-time database check...")
        try:
            db = get_db()
            db.execute("SELECT 1 FROM users LIMIT 1").fetchone()
            print("Database check passed. 'users' table found.")
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            if "no such table" in str(e):
                print("Tables not found. Initializing database now...")
                init_db()
            else:
                print(f"An unexpected database error occurred: {e}")
        finally:
            DB_INITIALIZED = True


# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "info"

# --- User Model for Flask-Login ---
class User(UserMixin):
    def __init__(self, id, username, password_hash, is_admin=False):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = is_admin

    @staticmethod
    def get(user_id):
        db = get_db()
        user_data = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user_data:
            return None
        return User(user_data['id'], user_data['username'], user_data['password_hash'], user_data['is_admin'])

    @staticmethod
    def get_by_username(username):
        db = get_db()
        user_data = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not user_data:
            return None
        return User(user_data['id'], user_data['username'], user_data['password_hash'], user_data['is_admin'])

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# --- Jinja Custom Filter ---
def datetimeformat(value, format_str='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, str) and value.lower() == 'now':
        return datetime.now().strftime(format_str)
    if isinstance(value, datetime):
         return value.strftime(format_str)
    try:
        dt_obj = datetime.strptime(str(value), '%Y-%m-%d')
        return dt_obj.strftime(format_str)
    except (ValueError, TypeError):
        return value
app.jinja_env.filters['datetimeformat'] = datetimeformat

# --- Database Helper Functions ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        # Use the DATABASE_PATH variable to connect
        db = g._database = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
    print("Initialized the database.")

@app.cli.command('init-db')
def init_db_command():
    init_db()

def query_db(query, args=(), one=False):
    db = get_db()
    cur = db.cursor()
    
    # PostgreSQL uses %s, SQLite uses ?
    if DATABASE_URL:
        query = query.replace('?', '%s')
    
    cur.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    db = get_db()
    cur = db.cursor()
    
    if DATABASE_URL:
        query = query.replace('?', '%s')
        
    cur.execute(query, args)
    db.commit()
    
    last_id = None
    # Getting last inserted ID is different in PostgreSQL
    if DATABASE_URL and "INSERT" in query.upper():
        # This is a simple approach, works if your table has an 'id' primary key
        # and the query returns the id. A more robust way needs RETURNING id.
        # Let's adjust the query slightly for this.
        # For now, we'll skip getting last_id for PG to avoid complexity.
        # If you need last_id, the INSERT queries need to be changed to "INSERT ... RETURNING id"
        pass
    elif not DATABASE_URL:
         last_id = cur.lastrowid
         
    cur.close()
    return last_id

# --- Company Details Helper ---
def get_company_details():
    return query_db("SELECT * FROM company_details WHERE id = 1", one=True)

# --- Context Processor ---
@app.context_processor
def inject_global_vars():
    return dict(company_details=get_company_details(), _year=datetime.utcnow().year, current_user=current_user)

# --- Custom Decorator for Admin Access ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('index'))
            # To show a 403 Forbidden error page directly:
            # abort(403) # Make sure to create templates/errors/403.html if you use this
        return f(*args, **kwargs)
    return decorated_function

# @app.errorhandler(403) # Uncomment if you have templates/errors/403.html
# def forbidden_page(error):
#     return render_template("errors/403.html"), 403

# --- Authentication Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # Check if any users already exist in the database
    user_count = query_db("SELECT COUNT(id) as count FROM users", one=True)['count']

    if request.method == 'POST':
        if user_count > 0: # If users exist, public registration is closed
            flash('Public registration is currently closed. Please contact an administrator or Developer Mushfiq.', 'warning')
            return redirect(url_for('login')) # Or stay on register page with message

        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password or not confirm_password:
            flash('All fields are required.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match.', 'error')
        # No need to check if username exists if user_count is 0, as it will be the first
        # else: # This else was for the User.get_by_username check which is not needed for the first user
        
        # The first user to register becomes an admin
        is_first_admin = (user_count == 0)
        
        hashed_password = generate_password_hash(password)
        try:
            execute_db("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                       [username, hashed_password, is_first_admin]) # is_first_admin will be 1 (True) or 0 (False)
            
            if is_first_admin:
                flash('Admin registration successful! You are the first admin. Please log in.', 'success')
            else: # This branch should not be hit if user_count > 0 blocks POST
                flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError: # Should only happen if somehow two try to register at exact same microsecond as first user
            flash('Username already taken or a database error occurred.', 'error')
        except Exception as e:
            flash(f'An error occurred during registration: {e}', 'error')
        
        # If POST fails (and wasn't blocked by user_count > 0), re-render with username
        return render_template('register.html', username=username, registration_allowed=(user_count == 0))


    # For GET request
    registration_allowed = (user_count == 0)
    if not registration_allowed and user_count > 0: # If GET and registration is closed
        flash('Public registration is currently closed. Please contact an administrator or Developer Mushfiq.', 'warning')
        # Optionally redirect to login, or show a simpler register page
        # return redirect(url_for('login'))
    
    return render_template('register.html', registration_allowed=registration_allowed)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    # Determine if public registration is allowed (for dynamic link on login page)
    user_count_result = query_db("SELECT COUNT(id) as count FROM users", one=True)
    user_count = user_count_result['count'] if user_count_result else 0 # Handle case of no users table yet or error
    registration_allowed = (user_count == 0) # Public registration is allowed only if no users exist

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = True if request.form.get('remember') else False
        user = User.get_by_username(username)

        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid username or password.', 'error')
            # Pass username back to pre-fill the form and registration_allowed status
            return render_template('login.html', username=username, registration_allowed=registration_allowed)
        else:
            login_user(user, remember=remember)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
    
    # For GET request
    return render_template('login.html', registration_allowed=registration_allowed)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Main Application Routes ---
@app.route('/')
@login_required
def index():
    # --- Client Balances and Total Receivables (Existing) ---
    clients_with_balances_query = """
        SELECT c.id, c.name, c.contact_number, COALESCE(SUM(t.debit - t.credit), 0) as balance
        FROM clients c LEFT JOIN transactions t ON c.id = t.client_id
        GROUP BY c.id, c.name, c.contact_number ORDER BY balance DESC, c.name ASC;
    """
    clients = query_db(clients_with_balances_query)
    total_receivables = sum(client['balance'] for client in clients)

    # --- Chart Data: Top 5 Clients by Balance ---
    top_clients_data = sorted([c for c in clients if c['balance'] > 0], key=lambda x: x['balance'], reverse=True)[:5]
    top_clients_labels = [client['name'] for client in top_clients_data]
    top_clients_values = [client['balance'] for client in top_clients_data]

    # --- Chart Data: Monthly Conveyance Expenses (Last 6 Months) ---
    # Get current date
    today = datetime.today()
    monthly_expenses_labels = []
    monthly_expenses_values = []
    
    # Create a dictionary to store expenses for the last 6 months, initialized to 0
    # Key: 'YYYY-MM', Value: total_expense
    expenses_by_month = defaultdict(float)

    for i in range(5, -1, -1): # Iterate from 5 months ago to current month
        # Calculate the month and year for the iteration
        month_date = today.replace(day=1) # Start with the first day of the current month
        # Subtract months. This logic needs to be careful with year boundaries.
        # A more robust way is to iterate and subtract one month at a time.
        current_iter_month = month_date.month - i
        current_iter_year = month_date.year
        if current_iter_month <= 0:
            current_iter_month += 12
            current_iter_year -=1
        
        month_label = datetime(current_iter_year, current_iter_month, 1).strftime('%b %Y') # e.g., May 2024
        monthly_expenses_labels.append(month_label)
        
        # Store the 'YYYY-MM' key for querying and summing
        db_month_key = datetime(current_iter_year, current_iter_month, 1).strftime('%Y-%m')
        expenses_by_month[db_month_key] = 0 # Initialize if not already present

    # Fetch expenses grouped by month from DB
    # This query gets all expenses grouped by 'YYYY-MM'
    # We then filter for the last 6 months in Python
    conveyance_expenses_query = """
        SELECT strftime('%Y-%m', bill_date) as month_year, SUM(amount) as total_amount
        FROM conveyance_bills
        GROUP BY month_year
        ORDER BY month_year DESC;
    """
    all_monthly_expenses_from_db = query_db(conveyance_expenses_query)

    for expense_entry in all_monthly_expenses_from_db:
        month_year_key = expense_entry['month_year']
        if month_year_key in expenses_by_month: # If this month is in our target 6 months
             expenses_by_month[month_year_key] = expense_entry['total_amount']

    # Populate an ordered list of values for the chart based on the ordered labels
    for i in range(5, -1, -1):
        month_date = today.replace(day=1)
        current_iter_month = month_date.month - i
        current_iter_year = month_date.year
        if current_iter_month <= 0:
            current_iter_month += 12
            current_iter_year -=1
        db_month_key = datetime(current_iter_year, current_iter_month, 1).strftime('%Y-%m')
        monthly_expenses_values.append(expenses_by_month[db_month_key])


    # --- Recent Transactions (Existing) ---
    recent_transactions_query = """
        SELECT t.*, c.name as client_name FROM transactions t JOIN clients c ON t.client_id = c.id
        ORDER BY t.transaction_date DESC, t.id DESC LIMIT 5;
    """
    recent_transactions = query_db(recent_transactions_query)

    # --- Conveyance Expenses for current month display card (Existing) ---
    current_month_start_str = today.strftime('%Y-%m-01')
    current_month_conveyance_query = "SELECT COALESCE(SUM(amount), 0) as total_monthly_expense FROM conveyance_bills WHERE bill_date >= ?;"
    monthly_conveyance_data = query_db(current_month_conveyance_query, [current_month_start_str], one=True)
    current_month_conveyance_total = monthly_conveyance_data['total_monthly_expense'] if monthly_conveyance_data else 0

    # --- Recent Conveyance Bills (Existing) ---
    recent_conveyance_bills_query = "SELECT * FROM conveyance_bills ORDER BY bill_date DESC, id DESC LIMIT 5;"
    recent_conveyance_bills = query_db(recent_conveyance_bills_query)

    return render_template('index.html',
                           clients=clients,
                           total_receivables=total_receivables,
                           recent_transactions=recent_transactions,
                           current_month_conveyance_total=current_month_conveyance_total,
                           recent_conveyance_bills=recent_conveyance_bills,
                           current_month_display=datetime.now().strftime("%B %Y"),
                           # Chart Data
                           top_clients_labels=top_clients_labels,
                           top_clients_values=top_clients_values,
                           monthly_expenses_labels=monthly_expenses_labels,
                           monthly_expenses_values=monthly_expenses_values
                           )

@app.route('/add_client', methods=['GET', 'POST'])
@login_required
def add_client():
    if request.method == 'POST':
        name = request.form['name']
        contact_number = request.form['contact_number']
        if not name:
            flash('Client name is required!', 'error')
        else:
            try:
                execute_db("INSERT INTO clients (name, contact_number) VALUES (?, ?)", [name, contact_number])
                flash(f'Client "{name}" added successfully!', 'success')
                return redirect(url_for('index'))
            except sqlite3.IntegrityError:
                flash(f'Client name "{name}" already exists.', 'error')
            except Exception as e:
                flash(f'An error occurred: {e}', 'error')
        return render_template('add_client.html', name=name, contact_number=contact_number)
    return render_template('add_client.html')

@app.route('/client/<int:client_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_client(client_id):
    client = query_db("SELECT * FROM clients WHERE id = ?", [client_id], one=True)
    if not client:
        flash('Client not found.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        contact_number = request.form['contact_number']
        if not name:
            flash('Client name is required!', 'error')
        else:
            try:
                existing_client_with_name = query_db("SELECT id FROM clients WHERE name = ? AND id != ?", [name, client_id], one=True)
                if existing_client_with_name:
                    flash(f'Another client with the name "{name}" already exists.', 'error')
                else:
                    execute_db("UPDATE clients SET name = ?, contact_number = ? WHERE id = ?", [name, contact_number, client_id])
                    flash(f'Client "{name}" updated successfully!', 'success')
                    return redirect(url_for('index'))
            except Exception as e:
                flash(f'An error occurred: {e}', 'error')
        return render_template('edit_client.html', client={'id': client_id, 'name': name, 'contact_number': contact_number})
    return render_template('edit_client.html', client=client)

@app.route('/client/<int:client_id>/delete', methods=['POST'])
@login_required
@admin_required # <<< CORRECT VERSION WITH ADMIN CHECK
def delete_client(client_id):
    client = query_db("SELECT name FROM clients WHERE id = ?", [client_id], one=True)
    if not client:
        flash('Client not found.', 'error')
        return redirect(url_for('index'))
    try:
        transactions_exist = query_db("SELECT 1 FROM transactions WHERE client_id = ? LIMIT 1", [client_id], one=True)
        if transactions_exist:
            flash(f'Cannot delete client "{client["name"]}" as they have existing transactions. Please delete their transactions first (or an admin can override).', 'error')
            return redirect(url_for('index'))
        execute_db("DELETE FROM clients WHERE id = ?", [client_id])
        flash(f'Client "{client["name"]}" deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting client: {e}', 'error')
    return redirect(url_for('index'))

@app.route('/client/<int:client_id>/add_transaction', methods=['GET', 'POST'])
@login_required
def add_transaction(client_id):
    client = query_db("SELECT * FROM clients WHERE id = ?", [client_id], one=True)
    if not client:
        flash('Client not found.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        transaction_date = request.form['transaction_date']
        fabrics_type = request.form.get('fabrics_type')
        design_code = request.form.get('design_code')
        qty_str = request.form.get('qty')
        transaction_mode = request.form['transaction_mode']
        narration = request.form.get('narration')
        chq_no = request.form.get('chq_no')
        challan_voucher_no = request.form.get('challan_voucher_no')
        debit_str = request.form.get('debit', '0')
        credit_str = request.form.get('credit', '0')
        if not transaction_date:
            flash('Transaction date is required.', 'error')
        try:
            qty = float(qty_str) if qty_str else None
            debit = float(debit_str) if debit_str else 0.0
            credit = float(credit_str) if credit_str else 0.0
        except ValueError:
            flash('Quantity, Debit, and Credit must be valid numbers.', 'error')
            return render_template('add_transaction.html', client=client, form_data=request.form)
        if debit == 0.0 and credit == 0.0:
            flash('Either Debit or Credit amount must be provided.', 'error')
        elif debit < 0 or credit < 0:
            flash('Debit and Credit amounts cannot be negative.', 'error')
        else:
            try:
                execute_db("""
                    INSERT INTO transactions (client_id, transaction_date, fabrics_type, design_code, qty,
                                              transaction_mode, narration, chq_no, challan_voucher_no,
                                              debit, credit)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, [client_id, transaction_date, fabrics_type, design_code, qty,
                      transaction_mode, narration, chq_no, challan_voucher_no,
                      debit, credit])
                flash('Transaction added successfully!', 'success')
                return redirect(url_for('client_ledger', client_id=client_id))
            except Exception as e:
                flash(f'An error occurred: {e}', 'error')
        return render_template('add_transaction.html', client=client, form_data=request.form)
    default_date = datetime.now().strftime('%Y-%m-%d')
    return render_template('add_transaction.html', client=client, default_date=default_date)

@app.route('/transaction/<int:transaction_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_transaction(transaction_id):
    transaction = query_db("SELECT * FROM transactions WHERE id = ?", [transaction_id], one=True)
    if not transaction:
        flash('Transaction not found.', 'error')
        return redirect(url_for('index'))
    client = query_db("SELECT * FROM clients WHERE id = ?", [transaction['client_id']], one=True)
    if not client:
        flash('Associated client not found.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        transaction_date = request.form['transaction_date']
        fabrics_type = request.form.get('fabrics_type')
        design_code = request.form.get('design_code')
        qty_str = request.form.get('qty')
        transaction_mode = request.form['transaction_mode']
        narration = request.form.get('narration')
        chq_no = request.form.get('chq_no')
        challan_voucher_no = request.form.get('challan_voucher_no')
        debit_str = request.form.get('debit', '0')
        credit_str = request.form.get('credit', '0')
        if not transaction_date:
            flash('Transaction date is required.', 'error')
        try:
            qty = float(qty_str) if qty_str else None
            debit = float(debit_str) if debit_str else 0.0
            credit = float(credit_str) if credit_str else 0.0
        except ValueError:
            flash('Quantity, Debit, and Credit must be valid numbers.', 'error')
            return render_template('edit_transaction.html', transaction=transaction, client=client, form_data=request.form)
        if debit == 0.0 and credit == 0.0:
            flash('Either Debit or Credit amount must be provided.', 'error')
        elif debit < 0 or credit < 0:
            flash('Debit and Credit amounts cannot be negative.', 'error')
        else:
            try:
                execute_db("""
                    UPDATE transactions SET
                    transaction_date = ?, fabrics_type = ?, design_code = ?, qty = ?,
                    transaction_mode = ?, narration = ?, chq_no = ?, challan_voucher_no = ?,
                    debit = ?, credit = ?
                    WHERE id = ?
                """, [transaction_date, fabrics_type, design_code, qty, transaction_mode,
                      narration, chq_no, challan_voucher_no, debit, credit, transaction_id])
                flash('Transaction updated successfully!', 'success')
                return redirect(url_for('client_ledger', client_id=transaction['client_id']))
            except Exception as e:
                flash(f'An error occurred while updating: {e}', 'error')
        return render_template('edit_transaction.html', transaction=transaction, client=client, form_data=request.form)
    return render_template('edit_transaction.html', transaction=transaction, client=client)

@app.route('/transaction/<int:transaction_id>/delete', methods=['POST'])
@login_required
@admin_required # <<< CORRECT VERSION WITH ADMIN CHECK
def delete_transaction(transaction_id):
    transaction_info = query_db("SELECT client_id FROM transactions WHERE id = ?", [transaction_id], one=True)
    if not transaction_info:
        flash('Transaction not found.', 'error')
        return redirect(request.referrer or url_for('index'))
    try:
        execute_db("DELETE FROM transactions WHERE id = ?", [transaction_id])
        flash('Transaction deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting transaction: {e}', 'error')
    return redirect(url_for('client_ledger', client_id=transaction_info['client_id']))

@app.route('/client/<int:client_id>/ledger')
@login_required
def client_ledger(client_id):
    client = query_db("SELECT id, name, contact_number FROM clients WHERE id = ?", [client_id], one=True)
    
    # --- DEBUGGING CLIENT OBJECT ---
    # print(f"--- Client Ledger Page ---")
    # print(f"Attempting to load ledger for client_id: {client_id}")
    # print(f"Client object from DB: {client}")
    # if client:
    #     print(f"Client Name: {client['name']}, Client ID: {client['id']}")
    # else:
    #     print("Client object is None or empty.")
    # --- END DEBUGGING ---

    if not client:
        flash('Client not found.', 'error')
        return redirect(url_for('index'))

    start_date_filter = request.args.get('start_date', '')
    end_date_filter = request.args.get('end_date', datetime.now().strftime('%Y-%m-%d'))

    # Using the more robust running balance query
    transaction_query_sql = """
        SELECT
            t.id, t.client_id, t.transaction_date, t.fabrics_type, t.design_code, t.qty,
            t.transaction_mode, t.narration, t.chq_no, t.challan_voucher_no,
            COALESCE(t.debit, 0) as debit, 
            COALESCE(t.credit, 0) as credit,
            (SELECT SUM(COALESCE(t2.debit,0) - COALESCE(t2.credit,0))
             FROM transactions t2
             WHERE t2.client_id = t.client_id AND 
                   ((t2.transaction_date < t.transaction_date) OR 
                    (t2.transaction_date = t.transaction_date AND t2.id <= t.id))
            ) as running_balance
        FROM transactions t
        WHERE t.client_id = ?
    """
    
    params = [client_id]
    conditions = []

    if start_date_filter:
        conditions.append("t.transaction_date >= ?")
        params.append(start_date_filter)
    if end_date_filter:
        conditions.append("t.transaction_date <= ?")
        params.append(end_date_filter)
    
    if conditions:
        transaction_query_sql += " AND " + " AND ".join(conditions)

    transaction_query_sql += " ORDER BY t.transaction_date ASC, t.id ASC"
    transactions_with_balance = query_db(transaction_query_sql, params)

    opening_balance = 0.0  # Ensure float
    if start_date_filter:
        ob_query = """
            SELECT SUM(COALESCE(debit,0) - COALESCE(credit,0)) as ob
            FROM transactions
            WHERE client_id = ? AND transaction_date < ?
        """
        ob_result = query_db(ob_query, [client_id, start_date_filter], one=True)
        if ob_result and ob_result['ob'] is not None:
            opening_balance = float(ob_result['ob'])

    total_debit = sum(t['debit'] for t in transactions_with_balance) # debit is already COALESCE'd to 0
    total_credit = sum(t['credit'] for t in transactions_with_balance) # credit is already COALESCE'd to 0
    
    final_closing_balance = transactions_with_balance[-1]['running_balance'] if transactions_with_balance and transactions_with_balance[-1]['running_balance'] is not None else opening_balance
    if final_closing_balance is None: # Should not happen if running_balance is calculated with COALESCE
        final_closing_balance = opening_balance

    return render_template('client_ledger.html',
                           client=client,
                           transactions=transactions_with_balance,
                           opening_balance=opening_balance,
                           total_debit=total_debit,
                           total_credit=total_credit,
                           closing_balance=float(final_closing_balance), # Ensure float
                           start_date=start_date_filter,
                           end_date=end_date_filter)

# --- Conveyance Bill Routes ---
@app.route('/conveyance_bills')
@login_required
def view_conveyance_bills():
    filter_date_from = request.args.get('filter_date_from', '')
    filter_date_to = request.args.get('filter_date_to', datetime.now().strftime('%Y-%m-%d'))
    filter_person_name = request.args.get('filter_person_name', '')
    query_sql = "SELECT * FROM conveyance_bills WHERE 1=1"
    params = []
    if filter_date_from:
        query_sql += " AND bill_date >= ?"
        params.append(filter_date_from)
    if filter_date_to:
        query_sql += " AND bill_date <= ?"
        params.append(filter_date_to)
    if filter_person_name:
        query_sql += " AND person_name LIKE ?"
        params.append(f"%{filter_person_name}%")
    query_sql += " ORDER BY bill_date DESC, id DESC"
    bills = query_db(query_sql, params)
    total_amount = sum(bill['amount'] for bill in bills)
    distinct_persons = query_db("SELECT DISTINCT person_name FROM conveyance_bills ORDER BY person_name ASC")
    return render_template('view_conveyance_bills.html',
                           bills=bills, total_amount=total_amount,
                           filter_date_from=filter_date_from, filter_date_to=filter_date_to,
                           filter_person_name=filter_person_name, distinct_persons=distinct_persons)

@app.route('/add_conveyance', methods=['GET', 'POST'])
@login_required
def add_conveyance():
    if request.method == 'POST':
        bill_date = request.form['bill_date']
        person_name = request.form['person_name']
        from_location = request.form.get('from_location')
        to_location = request.form.get('to_location')
        purpose = request.form.get('purpose')
        amount_str = request.form.get('amount')
        if not bill_date or not person_name or not amount_str:
            flash('Date, Person Name, and Amount are required.', 'error')
        else:
            try:
                amount = float(amount_str)
                if amount <= 0:
                    flash('Amount must be a positive number.', 'error')
                else:
                    execute_db("""
                        INSERT INTO conveyance_bills (bill_date, person_name, from_location, to_location, purpose, amount)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, [bill_date, person_name, from_location, to_location, purpose, amount])
                    flash('Conveyance bill added successfully!', 'success')
                    return redirect(url_for('view_conveyance_bills'))
            except ValueError:
                flash('Amount must be a valid number.', 'error')
            except Exception as e:
                flash(f'An error occurred: {e}', 'error')
        return render_template('add_conveyance.html', form_data=request.form)
    default_date = datetime.now().strftime('%Y-%m-%d')
    return render_template('add_conveyance.html', default_date=default_date)

@app.route('/conveyance/<int:bill_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_conveyance_bill(bill_id):
    bill = query_db("SELECT * FROM conveyance_bills WHERE id = ?", [bill_id], one=True)
    if not bill:
        flash('Conveyance bill not found.', 'error')
        return redirect(url_for('view_conveyance_bills'))
    if request.method == 'POST':
        bill_date = request.form['bill_date']
        person_name = request.form['person_name']
        from_location = request.form.get('from_location')
        to_location = request.form.get('to_location')
        purpose = request.form.get('purpose')
        amount_str = request.form.get('amount')
        if not bill_date or not person_name or not amount_str:
            flash('Date, Person Name, and Amount are required.', 'error')
        else:
            try:
                amount = float(amount_str)
                if amount <= 0:
                    flash('Amount must be a positive number.', 'error')
                else:
                    execute_db("""
                        UPDATE conveyance_bills SET
                        bill_date = ?, person_name = ?, from_location = ?, to_location = ?,
                        purpose = ?, amount = ?
                        WHERE id = ?
                    """, [bill_date, person_name, from_location, to_location, purpose, amount, bill_id])
                    flash('Conveyance bill updated successfully!', 'success')
                    return redirect(url_for('view_conveyance_bills'))
            except ValueError:
                flash('Amount must be a valid number.', 'error')
            except Exception as e:
                flash(f'An error occurred while updating: {e}', 'error')
        return render_template('edit_conveyance_bill.html', bill=bill, form_data=request.form)
    return render_template('edit_conveyance_bill.html', bill=bill)

@app.route('/conveyance/<int:bill_id>/delete', methods=['POST'])
@login_required
@admin_required # <<< CORRECT VERSION WITH ADMIN CHECK
def delete_conveyance_bill(bill_id):
    bill = query_db("SELECT id FROM conveyance_bills WHERE id = ?", [bill_id], one=True)
    if not bill:
        flash('Conveyance bill not found.', 'error')
    else:
        try:
            execute_db("DELETE FROM conveyance_bills WHERE id = ?", [bill_id])
            flash('Conveyance bill deleted successfully!', 'success')
        except Exception as e:
            flash(f'Error deleting conveyance bill: {e}', 'error')
    return redirect(url_for('view_conveyance_bills'))

# --- Report Routes ---
@app.route('/reports/monthly_client_summary', methods=['GET'])
@login_required
def monthly_client_summary_report():
    filter_year = request.args.get('filter_year', '')
    filter_month = request.args.get('filter_month', '') # Expects '01', '02', ..., '12'

    query_sql = """
        SELECT
            c.id as client_id,
            c.name as client_name,
            strftime('%Y', t.transaction_date) as year,
            strftime('%m', t.transaction_date) as month,
            SUM(t.debit) as total_debit,
            SUM(t.credit) as total_credit,
            (COALESCE(SUM(t.debit), 0) - COALESCE(SUM(t.credit), 0)) as net_change  -- Use COALESCE here
        FROM
            transactions t
        JOIN
            clients c ON t.client_id = c.id
        WHERE 1=1
    """
    params = []

    if filter_year:
        query_sql += " AND strftime('%Y', t.transaction_date) = ?"
        params.append(filter_year)
    if filter_month:
        query_sql += " AND strftime('%m', t.transaction_date) = ?"
        params.append(filter_month)

    query_sql += """
        GROUP BY
            c.id, c.name, year, month
        ORDER BY
            year DESC, month DESC, client_name ASC
    """
    summary_data = query_db(query_sql, params)

    distinct_years = query_db("SELECT DISTINCT strftime('%Y', transaction_date) as year FROM transactions ORDER BY year DESC")
    
    month_map = {
        "01": "January", "02": "February", "03": "March", "04": "April",
        "05": "May", "06": "June", "07": "July", "08": "August",
        "09": "September", "10": "October", "11": "November", "12": "December"
    }

    grand_total_debit = 0
    grand_total_credit = 0
    grand_total_net_change = 0

    if summary_data: # Ensure summary_data is not None or empty before trying to sum
        grand_total_debit = sum(item['total_debit'] for item in summary_data if item['total_debit'] is not None)
        grand_total_credit = sum(item['total_credit'] for item in summary_data if item['total_credit'] is not None)
        grand_total_net_change = sum(item['net_change'] for item in summary_data if item['net_change'] is not None)
    
    return render_template('report_monthly_client_summary.html',
                           summary_data=summary_data,
                           distinct_years=distinct_years,
                           month_map=month_map,
                           filter_year=filter_year,
                           filter_month=filter_month,
                           grand_total_debit=grand_total_debit,
                           grand_total_credit=grand_total_credit,
                           grand_total_net_change=grand_total_net_change)

# --- Admin Specific Routes ---
STATIC_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
MONOGRAM_UPLOAD_FOLDER = os.path.join(STATIC_FOLDER, 'img', 'monograms')
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg'} # Add more as needed

if not os.path.exists(MONOGRAM_UPLOAD_FOLDER):
    os.makedirs(MONOGRAM_UPLOAD_FOLDER)

def allowed_image_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


@app.route('/edit_company_details', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_company_details():
    company_info = get_company_details() # Get current details for form pre-fill and existing monogram

    if request.method == 'POST':
        company_name = request.form.get('company_name')
        address = request.form.get('address')
        contact_info = request.form.get('contact_info')
        
        new_monogram_path = company_info['monogram_path'] if company_info else None # Keep old path by default

        # --- Handle Monogram File Upload ---
        if 'monogram_file' in request.files:
            file = request.files['monogram_file']
            if file and file.filename != '': # Check if a new file was actually uploaded
                if allowed_image_file(file.filename):
                    filename = secure_filename(file.filename)
                    # To avoid overwriting, you might want to add a timestamp or UUID to filename
                    # For example: filename = f"{int(datetime.now().timestamp())}_{secure_filename(file.filename)}"
                    
                    # Delete old monogram if it exists and is different from the new one
                    if company_info and company_info['monogram_path'] and \
                       os.path.basename(company_info['monogram_path']) != filename: # Check base filename
                        old_file_full_path = os.path.join(STATIC_FOLDER, company_info['monogram_path'])
                        if os.path.exists(old_file_full_path):
                            try:
                                os.remove(old_file_full_path)
                                print(f"Deleted old monogram: {old_file_full_path}")
                            except Exception as e_del:
                                print(f"Error deleting old monogram {old_file_full_path}: {e_del}")
                                flash(f"Could not delete old monogram image. Please check server permissions.", "warning")
                    
                    # Save the new file
                    try:
                        file.save(os.path.join(MONOGRAM_UPLOAD_FOLDER, filename))
                        new_monogram_path = os.path.join('img', 'monograms', filename).replace('\\', '/') # Store relative path for url_for
                        flash('Monogram uploaded successfully!', 'success')
                    except Exception as e_save:
                        print(f"Error saving new monogram: {e_save}")
                        flash('Error uploading new monogram. Please try again.', 'error')
                        # Keep the old_monogram_path if new upload fails mid-process
                        new_monogram_path = company_info['monogram_path'] if company_info else None

                else:
                    flash('Invalid image file type. Allowed types: png, jpg, jpeg, gif, svg.', 'error')
                    # Keep the old_monogram_path if new upload is invalid type
                    new_monogram_path = company_info['monogram_path'] if company_info else None
            # If no new file is selected, 'file.filename' will be empty, and we keep the old path.
        
        # --- End Handle Monogram File Upload ---

        try:
            execute_db("""
                UPDATE company_details
                SET company_name = ?, monogram_path = ?, address = ?, contact_info = ?
                WHERE id = 1
            """, [company_name, new_monogram_path, address, contact_info])
            flash('Company details updated!', 'success')
            return redirect(url_for('edit_company_details')) # Redirect to same page to see changes
        except Exception as e:
            flash(f'Error updating company details in DB: {e}', 'error')

    # For GET request or if POST had an error that didn't redirect
    # Re-fetch in case of intermediate flash/redirect that didn't fully process
    company_info_display = get_company_details() 
    return render_template('edit_company_details.html', company_info=company_info_display)

@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    users = query_db("SELECT id, username, is_admin, created_at FROM users ORDER BY username")
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user_admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        is_admin = True if request.form.get('is_admin') else False
        if not username or not password or not confirm_password:
            flash('Username, Password, and Confirm Password are required.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match.', 'error')
        elif User.get_by_username(username):
            flash('Username already exists.', 'error')
        else:
            hashed_password = generate_password_hash(password)
            try:
                execute_db("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                           [username, hashed_password, is_admin])
                flash(f'User "{username}" created successfully!', 'success')
                return redirect(url_for('manage_users'))
            except Exception as e:
                flash(f'An error occurred: {e}', 'error')
        return render_template('admin/add_user.html', form_data=request.form)
    return render_template('admin/add_user.html')

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user_admin(user_id):
    user_to_edit = query_db("SELECT id, username, is_admin FROM users WHERE id = ?", [user_id], one=True)
    if not user_to_edit:
        flash('User not found.', 'error')
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        new_username = request.form.get('username').strip()
        new_is_admin = True if request.form.get('is_admin') else False
        new_password = request.form.get('password') # Optional new password

        # Check if new username is already taken by another user
        existing_user = query_db("SELECT id FROM users WHERE username = ? AND id != ?", [new_username, user_id], one=True)
        if existing_user:
            flash(f'Username "{new_username}" is already taken.', 'error')
        else:
            try:
                # Update username and admin status
                execute_db("UPDATE users SET username = ?, is_admin = ? WHERE id = ?",
                           [new_username, new_is_admin, user_id])
                
                # Update password ONLY if a new one was provided
                if new_password:
                    # You might want to add a password confirmation field too
                    hashed_password = generate_password_hash(new_password)
                    execute_db("UPDATE users SET password_hash = ? WHERE id = ?",
                               [hashed_password, user_id])
                    flash(f'User "{new_username}" details and password updated successfully!', 'success')
                else:
                    flash(f'User "{new_username}" details updated successfully!', 'success')
                
                return redirect(url_for('manage_users'))

            except Exception as e:
                flash(f'An error occurred: {e}', 'error')
        
        # If error, re-render form with submitted data
        form_data = dict(request.form)
        form_data['id'] = user_id
        return render_template('admin/edit_user.html', user=form_data)


    # For GET request
    return render_template('admin/edit_user.html', user=user_to_edit)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user_admin(user_id):
    # Prevent deleting oneself
    if user_id == current_user.id:
        flash("You cannot delete yourself.", "error")
        return redirect(url_for('manage_users'))

    # --- PREVENT DELETION OF THE FIRST ADMIN (USER ID 1) ---
    if user_id == 1:
        # flash("কাজটা তুমি ঠিক করলে না মাসুদ! The primary administrator (ID 1) cannot be deleted.", "error")
        flash("The primary administrator (User ID 1) cannot be deleted. (কাজটা তুমি ঠিক করলে না মাসুদ!)", "error")
        return redirect(url_for('manage_users'))
    # --- END PROTECTION FOR FIRST ADMIN ---

    user_to_delete = User.get(user_id) # User.get() fetches by id
    if not user_to_delete:
        flash("User not found.", "error")
    else:
        try:
            execute_db("DELETE FROM users WHERE id = ?", [user_id])
            flash(f"User '{user_to_delete.username}' deleted successfully.", "success")
        except Exception as e:
            flash(f"Error deleting user: {e}", "error")
    return redirect(url_for('manage_users'))
# ... (after your other routes, or group export routes together)

@app.route('/export/clients_csv')
@login_required
# @admin_required # Optional: Restrict to admins if desired
def export_clients_csv():
    clients_with_balances_query = """
        SELECT
            c.id,
            c.name,
            c.contact_number,
            COALESCE(SUM(t.debit - t.credit), 0) as balance
        FROM
            clients c
        LEFT JOIN
            transactions t ON c.id = t.client_id
        GROUP BY
            c.id, c.name, c.contact_number
        ORDER BY
            c.name ASC;
    """
    clients = query_db(clients_with_balances_query)

    # Prepare CSV
    si = io.StringIO()
    cw = csv.writer(si)

    # Write Header
    headers = ['Client ID', 'Client Name', 'Contact Number', 'Balance']
    cw.writerow(headers)

    # Write Data
    for client in clients:
        cw.writerow([client['id'], client['name'], client['contact_number'], f"{client['balance']:.2f}"])

    output = si.getvalue()
    si.close()

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition":
                 "attachment; filename=clients_report.csv"})

@app.route('/export/client_ledger_csv/<int:client_id>')
@login_required
def export_client_ledger_csv(client_id):
    client = query_db("SELECT * FROM clients WHERE id = ?", [client_id], one=True)
    if not client:
        flash('Client not found.', 'error')
        return redirect(url_for('index')) # Or appropriate error handling

    start_date_filter = request.args.get('start_date', '')
    end_date_filter = request.args.get('end_date', datetime.now().strftime('%Y-%m-%d'))

    query_sql = """
        SELECT
            t.transaction_date, t.fabrics_type, t.design_code, t.qty,
            t.transaction_mode, t.narration, t.chq_no, t.challan_voucher_no,
            t.debit, t.credit,
            (SELECT SUM(t2.debit - t2.credit)
             FROM transactions t2
             WHERE t2.client_id = t.client_id AND t2.id <= t.id
             ORDER BY t2.transaction_date, t2.id) as running_balance
        FROM transactions t
        WHERE client_id = ?
    """
    params = [client_id]

    if start_date_filter:
        query_sql += " AND transaction_date >= ?"
        params.append(start_date_filter)
    if end_date_filter:
        query_sql += " AND transaction_date <= ?"
        params.append(end_date_filter)
    query_sql += " ORDER BY transaction_date ASC, id ASC"
    transactions = query_db(query_sql, params)

    # Calculate Opening Balance for the CSV context
    opening_balance = 0
    if start_date_filter:
        ob_query = "SELECT SUM(debit - credit) as ob FROM transactions WHERE client_id = ? AND transaction_date < ?"
        ob_result = query_db(ob_query, [client_id, start_date_filter], one=True)
        if ob_result and ob_result['ob'] is not None:
            opening_balance = ob_result['ob']

    si = io.StringIO()
    cw = csv.writer(si)

    # Report Info
    cw.writerow(['Client Name:', client['name']])
    cw.writerow(['Contact:', client['contact_number'] if client['contact_number'] else 'N/A'])
    cw.writerow(['Period:', f"{start_date_filter if start_date_filter else 'Beginning'} to {end_date_filter}"])
    cw.writerow([]) # Empty line

    # Header
    headers = ['Date', 'Fabrics Type', 'Design Code', 'Qty', 'Transaction Mode',
               'Narration', 'Chq No.', 'Challan/Voucher No.', 'Debit', 'Credit', 'Balance']
    cw.writerow(headers)

    # Opening Balance if applicable
    if start_date_filter:
        # Create a list of empty strings for columns before 'Balance'
        ob_row = [''] * (len(headers) - 1)
        ob_row[0] = 'Opening Balance' # Description in first column or a narration-like column
        ob_row[-1] = f"{opening_balance:.2f}" # Balance in the last column
        cw.writerow(ob_row)


    # Data
    for trx in transactions:
        cw.writerow([
            trx['transaction_date'], trx['fabrics_type'], trx['design_code'], trx['qty'],
            trx['transaction_mode'], trx['narration'], trx['chq_no'], trx['challan_voucher_no'],
            f"{trx['debit']:.2f}", f"{trx['credit']:.2f}", f"{trx['running_balance']:.2f}"
        ])

    output = si.getvalue()
    si.close()

    filename = f"ledger_{client['name'].replace(' ', '_')}_{start_date_filter}_to_{end_date_filter}.csv"
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

@app.route('/export/conveyance_bills_csv')
@login_required
def export_conveyance_bills_csv():
    filter_date_from = request.args.get('filter_date_from', '')
    filter_date_to = request.args.get('filter_date_to', datetime.now().strftime('%Y-%m-%d'))
    filter_person_name = request.args.get('filter_person_name', '')

    query_sql = "SELECT * FROM conveyance_bills WHERE 1=1"
    params = []

    if filter_date_from:
        query_sql += " AND bill_date >= ?"
        params.append(filter_date_from)
    if filter_date_to:
        query_sql += " AND bill_date <= ?"
        params.append(filter_date_to)
    if filter_person_name:
        query_sql += " AND person_name LIKE ?"
        params.append(f"%{filter_person_name}%")
    query_sql += " ORDER BY bill_date DESC, id DESC"
    bills = query_db(query_sql, params)

    si = io.StringIO()
    cw = csv.writer(si)

    # Header
    headers = ['Bill ID', 'Date', 'Person Name', 'From Location', 'To Location', 'Purpose', 'Amount']
    cw.writerow(headers)

    # Data
    total_amount = 0
    for bill in bills:
        cw.writerow([
            bill['id'], bill['bill_date'], bill['person_name'],
            bill['from_location'], bill['to_location'], bill['purpose'],
            f"{bill['amount']:.2f}"
        ])
        total_amount += bill['amount']

    # Footer for total
    cw.writerow([]) # Empty line
    total_row = [''] * (len(headers) -1) # Empty cells for all but last
    total_row[-2] = "Total Amount:" # Description before amount
    total_row[-1] = f"{total_amount:.2f}"
    cw.writerow(total_row)


    output = si.getvalue()
    si.close()

    filename = f"conveyance_bills_{filter_date_from}_to_{filter_date_to}_{filter_person_name}.csv"
    filename = filename.replace(' ', '_').replace('%', '') # Sanitize filename
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

# --- App Configuration for Uploads ---
UPLOAD_FOLDER = 'uploads' # Create this folder in your project root
ALLOWED_EXTENSIONS = {'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ... (routes) ...

@app.route('/import/transactions_csv', methods=['GET', 'POST'])
@login_required
@admin_required # Usually an admin task
def import_transactions_csv():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Process the CSV file
            try:
                df = pd.read_csv(filepath)
                # Expected columns: Client Name, Date, Fabrics Type, Design Code, Qty, Transaction Mode, Narration, Chq No., Challan/Voucher No., Debit, Credit
                required_columns = ['Client Name', 'Date', 'Transaction Mode', 'Debit', 'Credit'] # Minimum required
                actual_columns = [col.strip() for col in df.columns]
                df.columns = actual_columns # Apply stripped column names

                # Validate headers
                missing_cols = [col for col in required_columns if col not in df.columns]
                if missing_cols:
                    flash(f'CSV is missing required columns: {", ".join(missing_cols)}', 'error')
                    os.remove(filepath) # Clean up uploaded file
                    return redirect(request.url)

                imported_count = 0
                skipped_rows = []
                db = get_db() # Get DB connection once

                for index, row in df.iterrows():
                    client_name = str(row['Client Name']).strip()
                    transaction_date = str(row['Date']).strip() # Expects YYYY-MM-DD or similar parseable by SQLite
                    transaction_mode = str(row['Transaction Mode']).strip()
                    
                    debit_str = str(row.get('Debit', '0')).strip()
                    credit_str = str(row.get('Credit', '0')).strip()

                    # Optional fields
                    fabrics_type = str(row.get('Fabrics Type', '')).strip()
                    design_code = str(row.get('Design Code', '')).strip()
                    qty_str = str(row.get('Qty', '')).strip()
                    narration = str(row.get('Narration', '')).strip()
                    chq_no = str(row.get('Chq No.', '')).strip()
                    challan_voucher_no = str(row.get('Challan/Voucher No.', '')).strip()


                    # Basic validation
                    if not client_name or not transaction_date or not transaction_mode:
                        skipped_rows.append({'row_num': index + 2, 'reason': 'Missing required basic info (Client, Date, Mode)'})
                        continue
                    
                    try:
                        debit = float(debit_str) if debit_str else 0.0
                        credit = float(credit_str) if credit_str else 0.0
                        qty = float(qty_str) if qty_str else None
                    except ValueError:
                        skipped_rows.append({'row_num': index + 2, 'reason': 'Invalid number for Qty, Debit, or Credit'})
                        continue
                    
                    if debit == 0.0 and credit == 0.0:
                        skipped_rows.append({'row_num': index + 2, 'reason': 'Both Debit and Credit are zero.'})
                        continue


                    # Find client by name
                    client = query_db("SELECT id FROM clients WHERE name = ?", [client_name], one=True)
                    if not client:
                        skipped_rows.append({'row_num': index + 2, 'reason': f'Client "{client_name}" not found.'})
                        continue

                    client_id = client['id']

                    try:
                        # Check for potential duplicates before inserting (basic check)
                        # This is a simple check, might need to be more sophisticated based on your data
                        # For example, check for same client, date, amount, and narration
                        # existing_trx = query_db("""
                        #     SELECT 1 FROM transactions 
                        #     WHERE client_id = ? AND transaction_date = ? AND debit = ? AND credit = ? AND narration = ? 
                        #     LIMIT 1
                        # """, [client_id, transaction_date, debit, credit, narration], one=True)
                        
                        # if existing_trx:
                        #     skipped_rows.append({'row_num': index + 2, 'reason': 'Potential duplicate transaction.'})
                        #     continue

                        execute_db("""
                            INSERT INTO transactions (client_id, transaction_date, fabrics_type, design_code, qty,
                                                      transaction_mode, narration, chq_no, challan_voucher_no,
                                                      debit, credit)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, [client_id, transaction_date, fabrics_type, design_code, qty,
                              transaction_mode, narration, chq_no, challan_voucher_no,
                              debit, credit])
                        imported_count += 1
                    except Exception as e_insert:
                        skipped_rows.append({'row_num': index + 2, 'reason': f'DB Insert Error: {str(e_insert)[:50]}'}) # Keep error short

                os.remove(filepath) # Clean up uploaded file
                
                success_msg = f'{imported_count} transactions imported successfully.'
                if skipped_rows:
                    success_msg += f' {len(skipped_rows)} rows were skipped.'
                    flash(success_msg, 'warning')
                    # Store skipped_rows in session to display them, or pass directly if small
                    # For simplicity, just flashing a summary for now
                    for skipped in skipped_rows[:5]: # Show first 5 skipped reasons
                         flash(f"Skipped Row {skipped['row_num']}: {skipped['reason']}", "danger")
                    if len(skipped_rows) > 5:
                        flash("...and more rows skipped. Check CSV formatting and client names.", "danger")

                else:
                    flash(success_msg, 'success')
                return redirect(url_for('index')) # Or to a summary page

            except pd.errors.EmptyDataError:
                flash('The uploaded CSV file is empty.', 'error')
                if os.path.exists(filepath): os.remove(filepath)
                return redirect(request.url)
            except Exception as e:
                flash(f'Error processing CSV file: {e}', 'error')
                if os.path.exists(filepath): os.remove(filepath)
                return redirect(request.url)
        else:
            flash('Invalid file type. Please upload a CSV file.', 'error')
            return redirect(request.url)

    return render_template('import_transactions.html')

# --- Routes for Daily Production ---

@app.route('/production/daily_report', methods=['GET', 'POST'])
@login_required
def daily_production_report():
    if request.method == 'POST': # Handles adding new production entries
        production_date = request.form.get('production_date')
        machine_number = request.form.get('machine_number')
        design_number = request.form.get('design_number')
        client_name_form = request.form.get('client_name') # Use different var name to avoid clash
        total_production_str = request.form.get('total_production')
        production_unit = request.form.get('production_unit', 'yards')

        if not all([production_date, machine_number, design_number, total_production_str]):
            flash('Date, Machine No., Design No., and Total Production are required.', 'error')
        else:
            try:
                total_production = float(total_production_str)
                if total_production <= 0:
                    flash('Total Production must be a positive number.', 'error')
                else:
                    execute_db("""
                        INSERT INTO daily_production
                        (production_date, machine_number, design_number, client_name, total_production, production_unit)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, [production_date, machine_number, design_number, client_name_form, total_production, production_unit])
                    flash('Production entry added successfully!', 'success')
            except ValueError:
                flash('Total Production must be a valid number.', 'error')
            except Exception as e:
                flash(f'An error occurred: {e}', 'error')
        # Form data for re-rendering is handled below by fetching current request args for filters

    # For GET request or after POST (to show list with filters applied)
    filter_specific_date = request.args.get('filter_specific_date', '') # New: YYYY-MM-DD
    filter_client_name = request.args.get('filter_client_name', '')   # New
    filter_year = request.args.get('filter_year', '') # Keep for broader view or if date is not set

    query = "SELECT * FROM daily_production WHERE 1=1"
    params = []
    
    # Apply filters
    if filter_specific_date:
        query += " AND production_date = ?"
        params.append(filter_specific_date)
        # If specific date is chosen, year filter becomes less relevant for this query
        # but can be kept for the filter UI pre-selection
    elif filter_year: # Only apply year filter if specific date is not set
        query += " AND strftime('%Y', production_date) = ?"
        params.append(filter_year)
        
    if filter_client_name:
        query += " AND client_name LIKE ?"
        params.append(f"%{filter_client_name}%") # Partial match

    query += " ORDER BY production_date DESC, id DESC"
    production_entries = query_db(query, params)

    # For filter dropdowns/datalists
    distinct_years_for_filter = query_db("SELECT DISTINCT strftime('%Y', production_date) as year FROM daily_production ORDER BY year DESC")
    distinct_clients_for_filter = query_db("SELECT DISTINCT client_name FROM daily_production WHERE client_name IS NOT NULL AND client_name != '' ORDER BY client_name ASC")
    
    default_date_form = datetime.now().strftime('%Y-%m-%d') # For the "Add New Entry" form

    return render_template('production/daily_production_report.html',
                           production_entries=production_entries,
                           form_data=request.form if request.method == 'POST' and any(request.form.values()) else {},
                           default_date_form=default_date_form,
                           distinct_years_for_filter=distinct_years_for_filter, # Renamed for clarity
                           distinct_clients_for_filter=distinct_clients_for_filter, # Renamed
                           filter_specific_date=filter_specific_date,
                           filter_client_name=filter_client_name,
                           filter_year=filter_year) # Pass current year filter value



@app.route('/export/production_csv')
@login_required
def export_production_csv():
    filter_year = request.args.get('filter_year', '')
    filter_month = request.args.get('filter_month', '')

    query = "SELECT * FROM daily_production WHERE 1=1"
    params = []
    filename_parts = ["production_report"]

    if filter_year and filter_month:
        query += " AND production_date LIKE ?"
        params.append(f"{filter_year}-{filter_month}-%")
        filename_parts.append(f"{filter_year}-{filter_month}")
    elif filter_year:
        query += " AND production_date LIKE ?"
        params.append(f"{filter_year}-%")
        filename_parts.append(filter_year)
    
    query += " ORDER BY production_date DESC, id DESC"
    entries = query_db(query, params)

    si = io.StringIO()
    cw = csv.writer(si)
    headers = ['ID', 'Date', 'Machine No.', 'Design No.', 'Client Name', 'Total Production', 'Unit']
    cw.writerow(headers)
    for entry in entries:
        cw.writerow([
            entry['id'], entry['production_date'], entry['machine_number'], entry['design_number'],
            entry['client_name'], entry['total_production'], entry['production_unit']
        ])
    
    output = si.getvalue()
    si.close()
    filename = "_".join(filename_parts) + ".csv"
    return Response(output, mimetype="text/csv", headers={"Content-disposition": f"attachment; filename={filename}"})

# PDF export for production is more complex and requires a library like WeasyPrint or ReportLab.
# We'll add a placeholder route for now.
@app.route('/export/production_pdf')
@login_required
def export_production_pdf():
    # This is a placeholder. Actual PDF generation is complex.
    # You'd typically render an HTML template specifically for PDF, then convert it.
    filter_year = request.args.get('filter_year', '')
    filter_month = request.args.get('filter_month', '')
    # Fetch data similar to CSV export
    # ...
    # For now, just redirect or show a message
    flash("PDF export for production reports is not yet implemented.", "info")
    return redirect(url_for('daily_production_report', filter_year=filter_year, filter_month=filter_month))

# You'll also need Edit/Delete routes for production entries later.
# @app.route('/production/<int:entry_id>/edit', methods=['GET', 'POST'])
# @app.route('/production/<int:entry_id>/delete', methods=['POST'])

@app.route('/production/<int:entry_id>/edit', methods=['GET', 'POST'])
@login_required
# @admin_required # Decide if only admins can edit, or any logged-in user
def edit_production_entry(entry_id):
    entry = query_db("SELECT * FROM daily_production WHERE id = ?", [entry_id], one=True)
    if not entry:
        flash('Production entry not found.', 'error')
        return redirect(url_for('daily_production_report'))

    if request.method == 'POST':
        production_date = request.form.get('production_date')
        machine_number = request.form.get('machine_number')
        design_number = request.form.get('design_number')
        client_name = request.form.get('client_name')
        total_production_str = request.form.get('total_production')
        production_unit = request.form.get('production_unit')

        if not all([production_date, machine_number, design_number, total_production_str, production_unit]):
            flash('All fields are required.', 'error')
        else:
            try:
                total_production = float(total_production_str)
                if total_production <= 0:
                    flash('Total Production must be a positive number.', 'error')
                else:
                    execute_db("""
                        UPDATE daily_production SET
                        production_date = ?, machine_number = ?, design_number = ?,
                        client_name = ?, total_production = ?, production_unit = ?
                        WHERE id = ?
                    """, [production_date, machine_number, design_number, client_name,
                          total_production, production_unit, entry_id])
                    flash('Production entry updated successfully!', 'success')
                    return redirect(url_for('daily_production_report'))
            except ValueError:
                flash('Total Production must be a valid number.', 'error')
            except Exception as e:
                flash(f'An error occurred: {e}', 'error')
        # Re-render form with submitted data if error
        return render_template('production/edit_production_entry.html', entry=request.form, entry_id=entry_id) # Pass form data

    # For GET request, pass existing entry data
    return render_template('production/edit_production_entry.html', entry=entry, entry_id=entry_id)


@app.route('/production/<int:entry_id>/delete', methods=['POST'])
@login_required
@admin_required # Deletion is usually an admin action
def delete_production_entry(entry_id):
    entry = query_db("SELECT id FROM daily_production WHERE id = ?", [entry_id], one=True)
    if not entry:
        flash('Production entry not found.', 'error')
    else:
        try:
            execute_db("DELETE FROM daily_production WHERE id = ?", [entry_id])
            flash('Production entry deleted successfully!', 'success')
        except Exception as e:
            flash(f'Error deleting production entry: {e}', 'error')
    return redirect(url_for('daily_production_report'))

# --- Routes for Managing Inventory Items (Admin) ---
@app.route('/admin/inventory_items', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_inventory_items():
    if request.method == 'POST': # Adding a new item
        product_type = request.form.get('product_type')
        sub_type = request.form.get('sub_type', '').strip()
        default_unit = request.form.get('default_unit')
        description = request.form.get('description', '').strip()

        if not product_type or not sub_type or not default_unit:
            flash('Product Type, Sub-Type, and Default Unit are required.', 'error')
        else:
            try:
                execute_db("""
                    INSERT INTO inventory_items (product_type, sub_type, default_unit, description)
                    VALUES (?, ?, ?, ?)
                """, [product_type, sub_type, default_unit, description])
                flash(f'Inventory item "{product_type} - {sub_type}" added successfully!', 'success')
            except sqlite3.IntegrityError: # Handles UNIQUE constraint violation
                flash(f'Inventory item "{product_type} - {sub_type}" already exists.', 'error')
            except Exception as e:
                flash(f'An error occurred: {e}', 'error')
        # Stay on page to show list and allow more additions
        # return redirect(url_for('manage_inventory_items')) # Not needed, will fall through to GET

    items = query_db("SELECT * FROM inventory_items ORDER BY product_type, sub_type")
    
    # Predefined product types and units for the form
    product_type_options = ['Fabric', 'Paper', 'Color', 'Chemical', 'Other'] # Customize as needed
    unit_options = ['yards', 'meters', 'kg', 'grams', 'liters', 'ml', 'sheets', 'pcs', 'rolls', 'Other'] # Customize

    return render_template('admin/manage_inventory_items.html',
                           items=items,
                           product_type_options=product_type_options,
                           unit_options=unit_options,
                           form_data=request.form if request.method == 'POST' else {})


@app.route('/admin/inventory_items/<int:item_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_inventory_item(item_id):
    # Check if item is used in transactions before deleting
    transactions_exist = query_db("SELECT 1 FROM inventory_transactions WHERE inventory_item_id = ? LIMIT 1", [item_id], one=True)
    if transactions_exist:
        flash('Cannot delete item. It is used in existing inventory transactions. Consider deactivating it instead (feature not yet implemented).', 'error')
    else:
        try:
            item = query_db("SELECT product_type, sub_type FROM inventory_items WHERE id = ?", [item_id], one=True)
            if item:
                execute_db("DELETE FROM inventory_items WHERE id = ?", [item_id])
                flash(f'Inventory item "{item["product_type"]} - {item["sub_type"]}" deleted.', 'success')
            else:
                flash('Item not found.', 'error')
        except Exception as e:
            flash(f'Error deleting item: {e}', 'error')
    return redirect(url_for('manage_inventory_items'))

# Edit Inventory Item route can be added later if needed.
@app.route('/admin/inventory_items/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_inventory_item(item_id):
    item = query_db("SELECT * FROM inventory_items WHERE id = ?", [item_id], one=True)
    if not item:
        flash('Inventory item not found.', 'error')
        return redirect(url_for('manage_inventory_items'))

    if request.method == 'POST':
        product_type = request.form.get('product_type')
        sub_type = request.form.get('sub_type', '').strip()
        default_unit = request.form.get('default_unit')
        description = request.form.get('description', '').strip()

        if not product_type or not sub_type or not default_unit:
            flash('Product Type, Sub-Type, and Default Unit are required.', 'error')
        else:
            try:
                # Check for uniqueness if product_type or sub_type changed
                existing_item = query_db(
                    "SELECT id FROM inventory_items WHERE product_type = ? AND sub_type = ? AND id != ?",
                    [product_type, sub_type, item_id], one=True
                )
                if existing_item:
                    flash(f'Another inventory item "{product_type} - {sub_type}" already exists.', 'error')
                else:
                    execute_db("""
                        UPDATE inventory_items SET
                        product_type = ?, sub_type = ?, default_unit = ?, description = ?
                        WHERE id = ?
                    """, [product_type, sub_type, default_unit, description, item_id])
                    flash('Inventory item updated successfully!', 'success')
                    return redirect(url_for('manage_inventory_items'))
            except sqlite3.IntegrityError: # Should be caught by the check above, but as a fallback
                 flash(f'Inventory item "{product_type} - {sub_type}" may already exist or another integrity issue.', 'error')
            except Exception as e:
                flash(f'An error occurred: {e}', 'error')
        # Re-render form with submitted data if error, passing original item_id
        # For the form values, it's better to construct a dictionary from request.form
        # and add the item_id for the action URL.
        form_values = dict(request.form)
        form_values['id'] = item_id # Add id for action URL in template
        return render_template('admin/edit_inventory_item.html', item=form_values, item_id=item_id,
                               product_type_options=['Fabric', 'Paper', 'Color', 'Chemical', 'Other'],
                               unit_options=['yards', 'meters', 'kg', 'grams', 'liters', 'ml', 'sheets', 'pcs', 'rolls', 'Other'])


    # For GET request
    product_type_options = ['Fabric', 'Paper', 'Color', 'Chemical', 'Other']
    unit_options = ['yards', 'meters', 'kg', 'grams', 'liters', 'ml', 'sheets', 'pcs', 'rolls', 'Other']
    return render_template('admin/edit_inventory_item.html', item=item, item_id=item_id,
                           product_type_options=product_type_options, unit_options=unit_options)

@app.route('/inventory/in', methods=['GET', 'POST'])
@login_required
def inventory_in_form():
    if request.method == 'POST':
        transaction_date = request.form.get('transaction_date')
        inventory_item_id_str = request.form.get('inventory_item_id')
        quantity_str = request.form.get('quantity')
        unit = request.form.get('unit') # Unit for this transaction
        total_price_str = request.form.get('total_price')
        client_name = request.form.get('client_name', '').strip() # Optional supplier/client
        remarks = request.form.get('remarks', '').strip()

        if not transaction_date or not inventory_item_id_str or not quantity_str or not unit:
            flash('Date, Item, Quantity, and Unit are required.', 'error')
        else:
            try:
                inventory_item_id = int(inventory_item_id_str)
                quantity = float(quantity_str)
                total_price = float(total_price_str) if total_price_str else None # Can be optional

                if quantity <= 0:
                    flash('Quantity must be a positive number.', 'error')
                else:
                    # Fetch item details to store redundantly and for validation
                    item_def = query_db("SELECT product_type, sub_type, default_unit FROM inventory_items WHERE id = ?",
                                        [inventory_item_id], one=True)
                    if not item_def:
                        flash('Selected inventory item not found. Please define it first.', 'error')
                    else:
                        execute_db("""
                            INSERT INTO inventory_transactions
                            (transaction_date, transaction_type, inventory_item_id, product_type, sub_type,
                             quantity, unit, total_price, client_name, remarks, user_id)
                            VALUES (?, 'IN', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, [transaction_date, inventory_item_id, item_def['product_type'], item_def['sub_type'],
                              quantity, unit, total_price, client_name, remarks, current_user.id])
                        flash(f'Stock IN recorded: {quantity} {unit} of {item_def["product_type"]} - {item_def["sub_type"]}.', 'success')
                        # return redirect(url_for('inventory_in_form')) # Stay on page or redirect to a list
            except ValueError:
                flash('Invalid number for Quantity or Total Price.', 'error')
            except Exception as e:
                flash(f'An error occurred: {e}', 'error')

    # For GET request or if POST had an error
    # Fetch defined inventory items for the dropdown
    # Group items by product_type for a grouped select or just list them
    inventory_item_options = query_db("SELECT id, product_type, sub_type, default_unit FROM inventory_items ORDER BY product_type, sub_type")
    
    # For unit dropdown consistency
    unit_options = ['yards', 'meters', 'kg', 'grams', 'liters', 'ml', 'sheets', 'pcs', 'rolls', 'Other']


    default_date_form = datetime.now().strftime('%Y-%m-%d')
    return render_template('inventory/stock_in_form.html',
                           inventory_item_options=inventory_item_options,
                           unit_options=unit_options,
                           default_date_form=default_date_form,
                           form_data=request.form if request.method == 'POST' else {})
@app.route('/inventory/out', methods=['GET', 'POST'])
@login_required
def inventory_out_form():
    if request.method == 'POST':
        transaction_date = request.form.get('transaction_date')
        inventory_item_id_str = request.form.get('inventory_item_id')
        quantity_str = request.form.get('quantity')
        unit = request.form.get('unit') # Unit for this transaction
        total_price_str = request.form.get('total_price')
        client_name = request.form.get('client_name', '').strip()
        remarks = request.form.get('remarks', '').strip()

        if not transaction_date or not inventory_item_id_str or not quantity_str or not unit or not client_name:
            flash('Date, Item, Quantity, Unit, and Client Name (Issued To) are required.', 'error')
        else:
            try:
                inventory_item_id = int(inventory_item_id_str)
                quantity_to_issue = float(quantity_str) # Renamed for clarity
                total_price = float(total_price_str) if total_price_str else None

                if quantity_to_issue <= 0:
                    flash('Quantity to issue must be a positive number.', 'error')
                else:
                    item_def = query_db("SELECT product_type, sub_type, default_unit FROM inventory_items WHERE id = ?",
                                        [inventory_item_id], one=True)
                    if not item_def:
                        flash('Selected inventory item not found.', 'error')
                    else:
                        # --- STOCK AVAILABILITY CHECK ---
                        # This check assumes all transactions for this item_id use the SAME unit for direct summation.
                        # If units can vary, this check needs to be much more complex with conversions.
                        current_stock_query = """
                            SELECT 
                                COALESCE(SUM(CASE transaction_type
                                            WHEN 'IN' THEN quantity
                                            WHEN 'OUT' THEN -quantity
                                            ELSE 0
                                       END), 0) as current_quantity
                            FROM inventory_transactions
                            WHERE inventory_item_id = ? 
                            -- AND unit = ? -- Add this if you only want to check stock for the specific unit being issued
                            -- If you don't check unit here, it assumes all quantities for the item are in a comparable unit
                        """
                        # For a simple check, we assume the `unit` selected in the form is the unit we care about
                        # This implies that the stock itself is maintained in this unit or directly comparable units.
                        # A more robust system would check against the item's primary stock unit after conversion.
                        
                        # Let's refine to check stock in the specific unit being issued if possible,
                        # or sum all and assume comparable for now.
                        # For a truly accurate check, you'd sum quantities for each unit type for an item,
                        # convert them to a base unit, then check availability.
                        # For now, the query sums all quantities for the item_id regardless of unit.
                        # This is a simplification. The dashboard also sums this way.

                        stock_data = query_db(current_stock_query, [inventory_item_id], one=True)
                        available_stock = stock_data['current_quantity'] if stock_data and stock_data['current_quantity'] is not None else 0.0

                        if quantity_to_issue > available_stock:
                            flash(f'Insufficient stock for "{item_def["product_type"]} - {item_def["sub_type"]}". ' +
                                  f'Available: {available_stock:.2f} (units based on transaction history). ' + # Clarify unit basis
                                  f'Requested: {quantity_to_issue:.2f} {unit}.', 'error')
                        else:
                            # Proceed with OUT transaction
                            execute_db("""
                                INSERT INTO inventory_transactions
                                (transaction_date, transaction_type, inventory_item_id, product_type, sub_type,
                                 quantity, unit, total_price, client_name, remarks, user_id)
                                VALUES (?, 'OUT', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, [transaction_date, inventory_item_id, item_def['product_type'], item_def['sub_type'],
                                  quantity_to_issue, unit, total_price, client_name, remarks, current_user.id])
                            flash(f'Stock OUT recorded: {quantity_to_issue:.2f} {unit} of {item_def["product_type"]} - {item_def["sub_type"]}.', 'success')
                            # return redirect(url_for('inventory_out_form')) # Or to dashboard/log
            except ValueError:
                flash('Invalid number for Quantity or Total Price.', 'error')
            except Exception as e:
                flash(f'An error occurred: {e}', 'error')
                # For debugging:
                # import traceback
                # traceback.print_exc()


    # For GET request or if POST had an error (to pre-fill form and dropdowns)
    inventory_item_options = query_db("SELECT id, product_type, sub_type, default_unit FROM inventory_items ORDER BY product_type, sub_type")
    unit_options = ['yards', 'meters', 'kg', 'grams', 'liters', 'ml', 'sheets', 'pcs', 'rolls', 'Other'] # Ensure this list is comprehensive
    default_date_form = datetime.now().strftime('%Y-%m-%d')

    return render_template('inventory/stock_out_form.html',
                           inventory_item_options=inventory_item_options,
                           unit_options=unit_options,
                           default_date_form=default_date_form,
                           form_data=request.form if request.method == 'POST' else {})

@app.route('/inventory/transactions')
@login_required
def inventory_transactions_list():
    # Filters
    filter_date_from = request.args.get('filter_date_from', '')
    filter_date_to = request.args.get('filter_date_to', '')
    filter_transaction_type = request.args.get('filter_transaction_type', '')
    filter_product_type = request.args.get('filter_product_type', '')
    filter_sub_type = request.args.get('filter_sub_type', '')
    filter_client_name = request.args.get('filter_client_name', '')

    # Original query had a JOIN which is good for displaying item names directly if needed,
    # but the inventory_transactions table itself stores product_type and sub_type.
    # Let's simplify the query for now to reduce potential JOIN issues and select directly
    # from inventory_transactions. We can add JOIN back if we need info from inventory_items
    # that's not already denormalized in inventory_transactions.
    
    # The original query was:
    # query = "SELECT it.*, ii.sub_type as item_sub_type_def, ii.product_type as item_prod_type_def FROM inventory_transactions it JOIN inventory_items ii ON it.inventory_item_id = ii.id WHERE 1=1"
    # This is fine, but let's ensure all aliases are used correctly or simplify if those aliases aren't used in template.

    # Let's use the simpler query based on the assumption that product_type and sub_type
    # are already stored in inventory_transactions.
    query = "SELECT * FROM inventory_transactions WHERE 1=1" # Simpler base query
    params = []

    if filter_date_from:
        query += " AND transaction_date >= ?" # Assuming 'transaction_date' is the column in inventory_transactions
        params.append(filter_date_from)
    if filter_date_to:
        query += " AND transaction_date <= ?"
        params.append(filter_date_to)
    if filter_transaction_type:
        query += " AND transaction_type = ?" # Assuming 'transaction_type'
        params.append(filter_transaction_type)
    if filter_product_type:
        query += " AND product_type = ?" # Assuming 'product_type' in inventory_transactions
        params.append(filter_product_type)
    if filter_sub_type:
        query += " AND sub_type LIKE ?" # Assuming 'sub_type' in inventory_transactions
        params.append(f"%{filter_sub_type}%")
    if filter_client_name:
        query += " AND client_name LIKE ?" # Assuming 'client_name' in inventory_transactions
        params.append(f"%{filter_client_name}%")

    query += " ORDER BY transaction_date DESC, id DESC" # Ensure table alias 'it.' is removed if not using JOIN
    
    transactions = query_db(query, params)

    # For filter dropdowns
    # Fetching from inventory_items is correct for populating filter options for defined types
    product_type_options_rows = query_db("SELECT DISTINCT product_type FROM inventory_items ORDER BY product_type")
    
    # Convert list of Row objects to list of strings
    product_type_options_list = []
    if product_type_options_rows:
        product_type_options_list = [pt_row['product_type'] for pt_row in product_type_options_rows]


    return render_template('inventory/transactions_list.html',
                           transactions=transactions,
                           filter_date_from=filter_date_from,
                           filter_date_to=filter_date_to,
                           filter_transaction_type=filter_transaction_type,
                           filter_product_type=filter_product_type,
                           product_type_options=product_type_options_list, # Pass the list of strings
                           filter_sub_type=filter_sub_type,
                           filter_client_name=filter_client_name)

@app.route('/inventory/dashboard', methods=['GET']) # Allow GET for filter params
@login_required
def store_dashboard():
    # --- Filters for IN/OUT Summaries ---
    filter_date_from = request.args.get('filter_date_from', '')
    filter_date_to = request.args.get('filter_date_to', '')
    # For IN/OUT summaries, we might want a separate product type filter
    # to avoid confusion with the overall stock display which shows all product types.
    filter_summary_product_type = request.args.get('filter_summary_product_type', '')

    # --- 1. Current Stock Available (remains unfiltered for overall view) ---
    current_stock_query = """
        SELECT ii.id as item_id, ii.product_type, ii.sub_type, ii.default_unit,
               COALESCE(SUM(CASE it.transaction_type WHEN 'IN' THEN it.quantity WHEN 'OUT' THEN -it.quantity ELSE 0 END), 0) as current_quantity
        FROM inventory_items ii
        LEFT JOIN inventory_transactions it ON ii.id = it.inventory_item_id
        GROUP BY ii.id, ii.product_type, ii.sub_type, ii.default_unit
        ORDER BY ii.product_type, ii.sub_type;
    """
    current_stock_list = query_db(current_stock_query)
    stock_by_product_type = defaultdict(list)
    for item_stock in current_stock_list:
        stock_by_product_type[item_stock['product_type']].append(item_stock)

    # --- 2. Total IN Summary (Now Filterable) ---
    total_in_summary_query_base = """
        SELECT COUNT(*) as total_in_transactions,
               COALESCE(SUM(quantity), 0) as total_quantity_received,
               COALESCE(SUM(total_price), 0) as total_value_spent
        FROM inventory_transactions
        WHERE transaction_type = 'IN'
    """
    in_params = []
    in_conditions = []

    if filter_date_from:
        in_conditions.append("transaction_date >= ?")
        in_params.append(filter_date_from)
    if filter_date_to:
        in_conditions.append("transaction_date <= ?")
        in_params.append(filter_date_to)
    if filter_summary_product_type:
        in_conditions.append("product_type = ?")
        in_params.append(filter_summary_product_type)
    
    if in_conditions:
        total_in_summary_query = total_in_summary_query_base + " AND " + " AND ".join(in_conditions)
    else:
        total_in_summary_query = total_in_summary_query_base
        
    total_in_summary = query_db(total_in_summary_query, tuple(in_params), one=True)


    # --- 3. Total OUT Summary (Now Filterable) ---
    total_out_summary_query_base = """
        SELECT COUNT(*) as total_out_transactions,
               COALESCE(SUM(quantity), 0) as total_quantity_issued,
               COALESCE(SUM(total_price), 0) as total_value_issued
        FROM inventory_transactions
        WHERE transaction_type = 'OUT'
    """
    out_params = []
    out_conditions = []

    if filter_date_from:
        out_conditions.append("transaction_date >= ?")
        out_params.append(filter_date_from)
    if filter_date_to:
        out_conditions.append("transaction_date <= ?")
        out_params.append(filter_date_to)
    if filter_summary_product_type:
        out_conditions.append("product_type = ?")
        out_params.append(filter_summary_product_type)

    if out_conditions:
        total_out_summary_query = total_out_summary_query_base + " AND " + " AND ".join(out_conditions)
    else:
        total_out_summary_query = total_out_summary_query_base

    total_out_summary = query_db(total_out_summary_query, tuple(out_params), one=True)
    
    # --- 4. Data for IN/OUT Summary Chart (e.g., by Product Type for the filtered period) ---
    # This chart will show total IN Qty vs total OUT Qty for each product type
    # within the filtered date range.
    in_out_chart_query = """
        SELECT
            product_type,
            SUM(CASE WHEN transaction_type = 'IN' THEN quantity ELSE 0 END) as total_in_qty,
            SUM(CASE WHEN transaction_type = 'OUT' THEN quantity ELSE 0 END) as total_out_qty
        FROM inventory_transactions
        WHERE 1=1 
    """
    chart_params = []
    chart_conditions = []

    if filter_date_from:
        chart_conditions.append("transaction_date >= ?")
        chart_params.append(filter_date_from)
    if filter_date_to:
        chart_conditions.append("transaction_date <= ?")
        chart_params.append(filter_date_to)
    # This chart will show all product types unless one is specifically chosen for summary cards
    if filter_summary_product_type:
        chart_conditions.append("product_type = ?")
        chart_params.append(filter_summary_product_type)

    if chart_conditions:
        in_out_chart_query += " AND " + " AND ".join(chart_conditions)
    
    in_out_chart_query += " GROUP BY product_type ORDER BY product_type"
    
    in_out_chart_data_rows = query_db(in_out_chart_query, tuple(chart_params))
    
    chart_labels = [row['product_type'] for row in in_out_chart_data_rows]
    chart_in_values = [row['total_in_qty'] for row in in_out_chart_data_rows]
    chart_out_values = [row['total_out_qty'] for row in in_out_chart_data_rows]


    # For filter dropdowns
    product_type_filter_options = query_db("SELECT DISTINCT product_type FROM inventory_items ORDER BY product_type")
    product_type_filter_options_list = [pt['product_type'] for pt in product_type_filter_options] if product_type_filter_options else []


    return render_template('inventory/store_dashboard.html',
                           stock_by_product_type=stock_by_product_type,
                           total_in_summary=total_in_summary,
                           total_out_summary=total_out_summary,
                           # Filters
                           filter_date_from=filter_date_from,
                           filter_date_to=filter_date_to,
                           filter_summary_product_type=filter_summary_product_type,
                           product_type_filter_options=product_type_filter_options_list,
                           # Chart Data
                           chart_labels=chart_labels,
                           chart_in_values=chart_in_values,
                           chart_out_values=chart_out_values
                           )

if __name__ == '__main__':
    app.run(debug=True)

# if __name__ == '__main__':
#     # For local development only, Railway uses gunicorn
#     app.run(debug=False, host='0.0.0.0') 