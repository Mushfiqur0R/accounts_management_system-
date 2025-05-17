import sqlite3
from flask import Flask, render_template, request, redirect, url_for, g, flash, abort # Single set of Flask imports
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user # Single set of Flask-Login imports
from functools import wraps

DATABASE = 'database.db'

app = Flask(__name__)
app.secret_key = '20250' # REMEMBER TO CHANGE THIS TO A STRONG, RANDOM KEY FOR PRODUCTION

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
        db = g._database = sqlite3.connect(DATABASE)
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
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password or not confirm_password:
            flash('All fields are required.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match.', 'error')
        elif User.get_by_username(username):
            flash('Username already exists.', 'error')
        else:
            hashed_password = generate_password_hash(password)
            try:
                execute_db("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           [username, hashed_password])
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                flash(f'An error occurred during registration: {e}', 'error')
        return render_template('register.html', username=username)
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = True if request.form.get('remember') else False
        user = User.get_by_username(username)
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid username or password.', 'error')
        else:
            login_user(user, remember=remember)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        return render_template('login.html', username=username)
    return render_template('login.html')

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
    # --- Client Balances and Total Receivables ---
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
            balance DESC, c.name ASC;
    """
    clients = query_db(clients_with_balances_query)
    total_receivables = sum(client['balance'] for client in clients)

    # --- Recent Transactions (e.g., last 5) ---
    recent_transactions_query = """
        SELECT
            t.*,
            c.name as client_name
        FROM
            transactions t
        JOIN
            clients c ON t.client_id = c.id
        ORDER BY
            t.transaction_date DESC, t.id DESC
        LIMIT 5;
    """
    recent_transactions = query_db(recent_transactions_query)

    # --- Conveyance Expenses (e.g., current month) ---
    current_month_start = datetime.now().strftime('%Y-%m-01')
    current_month_conveyance_query = """
        SELECT
            COALESCE(SUM(amount), 0) as total_monthly_expense
        FROM
            conveyance_bills
        WHERE
            bill_date >= ?;
    """
    # Note: For an exact current month, you'd also need an end date.
    # For simplicity, this gets expenses from the start of the current month onwards.
    # A more precise query for *only* the current month:
    # WHERE bill_date >= date('now', 'start of month') AND bill_date < date('now', 'start of month', '+1 month')
    # Or using Python to calculate end of month:
    # current_year = datetime.now().year
    # current_month_num = datetime.now().month
    # _, num_days = calendar.monthrange(current_year, current_month_num)
    # current_month_end = datetime(current_year, current_month_num, num_days).strftime('%Y-%m-%d')
    # params = [current_month_start, current_month_end]
    # query = "... WHERE bill_date BETWEEN ? AND ?"

    monthly_conveyance_data = query_db(current_month_conveyance_query, [current_month_start], one=True)
    current_month_conveyance_total = monthly_conveyance_data['total_monthly_expense'] if monthly_conveyance_data else 0

    # --- Recent Conveyance Bills (e.g., last 5) ---
    recent_conveyance_bills_query = """
        SELECT * FROM conveyance_bills
        ORDER BY bill_date DESC, id DESC
        LIMIT 5;
    """
    recent_conveyance_bills = query_db(recent_conveyance_bills_query)


    return render_template('index.html',
                           clients=clients, # Now includes balance
                           total_receivables=total_receivables,
                           recent_transactions=recent_transactions,
                           current_month_conveyance_total=current_month_conveyance_total,
                           recent_conveyance_bills=recent_conveyance_bills,
                           current_month_display=datetime.now().strftime("%B %Y")) # For display

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
    client = query_db("SELECT * FROM clients WHERE id = ?", [client_id], one=True)
    if not client:
        flash('Client not found.', 'error')
        return redirect(url_for('index'))
    start_date_filter = request.args.get('start_date', '')
    end_date_filter = request.args.get('end_date', datetime.now().strftime('%Y-%m-%d'))
    query = """
        SELECT *, (SELECT SUM(t2.debit - t2.credit)
                    FROM transactions t2
                    WHERE t2.client_id = t.client_id AND t2.id <= t.id
                    ORDER BY t2.transaction_date, t2.id) as running_balance
        FROM transactions t
        WHERE client_id = ?
    """
    params = [client_id]
    if start_date_filter:
        query += " AND transaction_date >= ?"
        params.append(start_date_filter)
    if end_date_filter:
        query += " AND transaction_date <= ?"
        params.append(end_date_filter)
    query += " ORDER BY transaction_date ASC, id ASC"
    transactions_with_balance = query_db(query, params)
    opening_balance = 0
    if start_date_filter:
        ob_query = "SELECT SUM(debit - credit) as ob FROM transactions WHERE client_id = ? AND transaction_date < ?"
        ob_result = query_db(ob_query, [client_id, start_date_filter], one=True)
        if ob_result and ob_result['ob'] is not None:
            opening_balance = ob_result['ob']
    total_debit = sum(t['debit'] for t in transactions_with_balance)
    total_credit = sum(t['credit'] for t in transactions_with_balance)
    closing_balance = transactions_with_balance[-1]['running_balance'] if transactions_with_balance else opening_balance
    return render_template('client_ledger.html',
                           client=client, transactions=transactions_with_balance,
                           opening_balance=opening_balance, total_debit=total_debit,
                           total_credit=total_credit, closing_balance=closing_balance,
                           start_date=start_date_filter, end_date=end_date_filter)

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
    filter_month = request.args.get('filter_month', '')
    query_sql = """
        SELECT
            c.id as client_id, c.name as client_name,
            strftime('%Y', t.transaction_date) as year, strftime('%m', t.transaction_date) as month,
            SUM(t.debit) as total_debit, SUM(t.credit) as total_credit,
            (SUM(t.debit) - SUM(t.credit)) as net_change
        FROM transactions t JOIN clients c ON t.client_id = c.id
        WHERE 1=1
    """
    params = []
    if filter_year:
        query_sql += " AND strftime('%Y', t.transaction_date) = ?"
        params.append(filter_year)
    if filter_month:
        query_sql += " AND strftime('%m', t.transaction_date) = ?"
        params.append(filter_month)
    query_sql += " GROUP BY c.id, c.name, year, month ORDER BY year DESC, month DESC, client_name ASC"
    summary_data = query_db(query_sql, params)
    distinct_years = query_db("SELECT DISTINCT strftime('%Y', transaction_date) as year FROM transactions ORDER BY year DESC")
    month_map = {"01":"Jan","02":"Feb","03":"Mar","04":"Apr","05":"May","06":"Jun","07":"Jul","08":"Aug","09":"Sep","10":"Oct","11":"Nov","12":"Dec"}
    grand_total_debit = sum(item['total_debit'] for item in summary_data)
    grand_total_credit = sum(item['total_credit'] for item in summary_data)
    grand_total_net_change = sum(item['net_change'] for item in summary_data)
    return render_template('report_monthly_client_summary.html',
                           summary_data=summary_data, distinct_years=distinct_years,
                           month_map=month_map, filter_year=filter_year, filter_month=filter_month,
                           grand_total_debit=grand_total_debit, grand_total_credit=grand_total_credit,
                           grand_total_net_change=grand_total_net_change)

# --- Admin Specific Routes ---
@app.route('/edit_company_details', methods=['GET', 'POST'])
@login_required
@admin_required # <<< CORRECT VERSION WITH ADMIN CHECK
def edit_company_details():
    company_info = get_company_details()
    if request.method == 'POST':
        company_name = request.form['company_name']
        monogram_path = request.form['monogram_path']
        address = request.form['address']
        contact_info = request.form['contact_info']
        execute_db("""
            UPDATE company_details SET company_name = ?, monogram_path = ?, address = ?, contact_info = ?
            WHERE id = 1
        """, [company_name, monogram_path, address, contact_info])
        flash('Company details updated!', 'success')
        return redirect(url_for('index'))
    return render_template('edit_company_details.html', company_info=company_info)

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

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user_admin(user_id):
    if user_id == current_user.id:
        flash("You cannot delete yourself.", "error")
        return redirect(url_for('manage_users'))
    user_to_delete = User.get(user_id)
    if not user_to_delete:
        flash("User not found.", "error")
    else:
        try:
            execute_db("DELETE FROM users WHERE id = ?", [user_id])
            flash(f"User '{user_to_delete.username}' deleted successfully.", "success")
        except Exception as e:
            flash(f"Error deleting user: {e}", "error")
    return redirect(url_for('manage_users'))

if __name__ == '__main__':
    app.run(debug=True)