-- Up
CREATE TABLE IF NOT EXISTS lost_clients (
    id INTEGER PRIMARY KEY,
    -- Keeping original ID for reference
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    domain TEXT,
    account_manager_id INTEGER,
    marketing_manager_id INTEGER,
    dev_manager_id INTEGER,
    am_head_id INTEGER,
    team_leader_id INTEGER,
    status TEXT,
    agreement_status TEXT,
    invoice_status TEXT,
    onboarding_by INTEGER,
    onboarding_date TEXT,
    onboarding_pdf_url TEXT,
    recurring_day INTEGER,
    contract_end_date TEXT,
    deleted_at TEXT DEFAULT (datetime('now', 'localtime'))
);

-- Down
DROP TABLE IF EXISTS lost_clients;