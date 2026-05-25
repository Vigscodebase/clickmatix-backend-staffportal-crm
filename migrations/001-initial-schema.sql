-- Up
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'staff',
  department TEXT,
  can_add INTEGER DEFAULT 0,
  can_edit INTEGER DEFAULT 0,
  can_delete INTEGER DEFAULT 0,
  permissions TEXT,
  location TEXT DEFAULT 'WFO',
  avatar_url TEXT,
  created_at TEXT DEFAULT (datetime('now')) 
);

    CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT,
      phone TEXT,
      domain TEXT,
      account_manager_id INTEGER,
      marketing_manager_id INTEGER,
      dev_manager_id INTEGER,
      am_head_id INTEGER,
      status TEXT DEFAULT 'Pending',
      agreement_status TEXT DEFAULT 'Pending',
      invoice_status TEXT DEFAULT 'Pending',
      onboarding_by INTEGER,
      onboarding_date TEXT,
      onboarding_pdf_url TEXT,
      recurring_day INTEGER,
      contract_end_date TEXT,
      FOREIGN KEY(account_manager_id) REFERENCES users(id),
      FOREIGN KEY(marketing_manager_id) REFERENCES users(id),
      FOREIGN KEY(dev_manager_id) REFERENCES users(id),
      FOREIGN KEY(am_head_id) REFERENCES users(id),
      FOREIGN KEY(onboarding_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS services (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      monthly_fee REAL DEFAULT 0,
      ad_spend REAL DEFAULT 0,
      tl_id INTEGER,
      status TEXT DEFAULT 'Hold',
      status_color TEXT DEFAULT 'Red',
      revenue_type TEXT DEFAULT 'Recurring',
      revenue_month TEXT,
      FOREIGN KEY(client_id) REFERENCES clients(id)
    );

        CREATE TABLE IF NOT EXISTS invoices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      amount REAL NOT NULL,
      status TEXT DEFAULT 'Pending',
      month TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(client_id) REFERENCES clients(id)
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      message TEXT NOT NULL,
      type TEXT,
      is_read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

-- Down
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS invoices;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS notifications;
-- (Add your other DROP TABLE commands here)