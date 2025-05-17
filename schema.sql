-- Client Information
DROP TABLE IF EXISTS clients;
CREATE TABLE clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    contact_number TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Transactions (Debtors Ledger)
DROP TABLE IF EXISTS transactions;
CREATE TABLE transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    transaction_date TEXT NOT NULL, -- Store as YYYY-MM-DD for easy sorting
    fabrics_type TEXT,
    design_code TEXT,
    qty REAL,
    transaction_mode TEXT,
    narration TEXT,
    chq_no TEXT,
    challan_voucher_no TEXT,
    debit REAL DEFAULT 0,
    credit REAL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients (id)
);

-- Company Details (for printing)
DROP TABLE IF EXISTS company_details;
CREATE TABLE company_details (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    company_name TEXT,
    monogram_path TEXT,
    address TEXT,
    contact_info TEXT
);

-- Insert a default placeholder for company details if it doesn't exist or you re-init
INSERT OR IGNORE INTO company_details (id, company_name, monogram_path, address, contact_info)
VALUES (1, 'Your Company Name', 'img/company_monogram.png', 'Your Company Address', 'Your Company Contact');

-- Conveyance Bills
DROP TABLE IF EXISTS conveyance_bills;
CREATE TABLE conveyance_bills (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bill_date TEXT NOT NULL, -- Store as YYYY-MM-DD
    person_name TEXT NOT NULL,
    from_location TEXT,
    to_location TEXT,
    purpose TEXT,
    amount REAL NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Users Table
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT 0, -- Optional: for future admin roles
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Optional: Create a default admin user (replace 'your_admin_password' with a real hashed password or hash it on first run)
-- For simplicity, we'll allow registration first.
-- INSERT OR IGNORE INTO users (username, password_hash, is_admin) VALUES ('admin', 'hashed_password_here', 1);