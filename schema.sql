-- PostgreSQL Schema for Accounts Management System

-- Drop tables in reverse order of creation due to dependencies, and use CASCADE
DROP TABLE IF EXISTS inventory_transactions, inventory_items, daily_production, conveyance_bills, company_details, transactions, clients, users CASCADE;

-- Users Table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Clients Table
CREATE TABLE clients (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    contact_number TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Client Transactions (Debtors Ledger) Table
CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    transaction_date DATE NOT NULL,
    fabrics_type TEXT,
    design_code TEXT,
    qty REAL,
    transaction_mode TEXT,
    narration TEXT,
    chq_no TEXT,
    challan_voucher_no TEXT,
    debit REAL DEFAULT 0,
    credit REAL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Company Details Table
CREATE TABLE company_details (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    company_name TEXT,
    monogram_path TEXT,
    address TEXT,
    contact_info TEXT
);

-- Insert a default row for company_details, using ON CONFLICT to avoid errors on re-run
INSERT INTO company_details (id, company_name, monogram_path, address, contact_info)
VALUES (1, 'Trims Mart', 'img/default_logo.png', 'Your Company Address', 'Your Contact Info')
ON CONFLICT (id) DO NOTHING;


-- Conveyance Bills Table
CREATE TABLE conveyance_bills (
    id SERIAL PRIMARY KEY,
    bill_date DATE NOT NULL,
    person_name TEXT NOT NULL,
    from_location TEXT,
    to_location TEXT,
    purpose TEXT,
    amount REAL NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Daily Production Report Table
CREATE TABLE daily_production (
    id SERIAL PRIMARY KEY,
    production_date DATE NOT NULL,
    machine_number TEXT NOT NULL,
    design_number TEXT NOT NULL,
    client_name TEXT,
    total_production REAL NOT NULL,
    production_unit TEXT NOT NULL DEFAULT 'yards',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Store Inventory Items Table
CREATE TABLE inventory_items (
    id SERIAL PRIMARY KEY,
    product_type TEXT NOT NULL,
    sub_type TEXT NOT NULL,
    default_unit TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (product_type, sub_type)
);

-- Store Inventory Transactions Table
CREATE TABLE inventory_transactions (
    id SERIAL PRIMARY KEY,
    transaction_date DATE NOT NULL,
    transaction_type TEXT NOT NULL, -- 'IN' or 'OUT'
    inventory_item_id INTEGER NOT NULL REFERENCES inventory_items(id) ON DELETE RESTRICT, -- Prevents deleting an item if it has transactions
    product_type TEXT NOT NULL,
    sub_type TEXT NOT NULL,
    quantity REAL NOT NULL,
    unit TEXT NOT NULL,
    total_price REAL,
    client_name TEXT,
    remarks TEXT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, -- If a user is deleted, the transaction remains but user_id becomes NULL
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);