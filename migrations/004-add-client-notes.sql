-- Up
CREATE TABLE IF NOT EXISTS client_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    client_id INTEGER, 
    content TEXT, 
    created_by INTEGER, 
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    FOREIGN KEY(client_id) REFERENCES clients(id),
    FOREIGN KEY(created_by) REFERENCES users(id)
);

-- Down
DROP TABLE IF EXISTS client_notes;