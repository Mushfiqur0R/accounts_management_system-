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

-- Daily Production Report
DROP TABLE IF EXISTS daily_production;
CREATE TABLE daily_production (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    production_date TEXT NOT NULL, -- YYYY-MM-DD
    machine_number TEXT NOT NULL, -- Store as text to allow for non-numeric machine IDs if ever needed
    design_number TEXT NOT NULL,
    client_name TEXT, -- Could be FK to clients table if strict, or text for flexibility
    total_production REAL NOT NULL,
    production_unit TEXT NOT NULL DEFAULT 'yards', -- e.g., yards, meters
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    -- user_id INTEGER, -- Optional: to track who entered it
    -- FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Store Inventory Items (Defines what items can be in stock)
-- This table helps in categorizing and managing stock items consistently.
DROP TABLE IF EXISTS inventory_items;
CREATE TABLE inventory_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_type TEXT NOT NULL, -- Fabric, Paper, Color (could be a SELECT in form)
    sub_type TEXT NOT NULL,     -- e.g., Linen, Red Dye, A4 Bond (unique with product_type)
    default_unit TEXT NOT NULL, -- yards, kg, sheets, pcs (default unit for this item)
    description TEXT,           -- Optional description
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (product_type, sub_type) -- Ensure no duplicate item definitions
);

-- Store Inventory Transactions (Records IN and OUT movements)
DROP TABLE IF EXISTS inventory_transactions;
CREATE TABLE inventory_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_date TEXT NOT NULL,    -- YYYY-MM-DD
    transaction_type TEXT NOT NULL,    -- 'IN' or 'OUT'
    inventory_item_id INTEGER NOT NULL, -- Foreign key to inventory_items
    -- We store product_type, sub_type, and unit again here for reporting convenience,
    -- though they could be joined from inventory_items.
    -- Storing them here also makes the transaction record self-contained if item definition changes.
    product_type TEXT NOT NULL,
    sub_type TEXT NOT NULL,
    quantity REAL NOT NULL,
    unit TEXT NOT NULL,                -- Unit used for THIS transaction
    total_price REAL,                  -- Optional, manually entered for this transaction
    client_name TEXT,                  -- Optional for IN, often required for OUT
    remarks TEXT,                      -- Optional notes for the transaction
    user_id INTEGER,                   -- Optional: track who made the transaction
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (inventory_item_id) REFERENCES inventory_items (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);