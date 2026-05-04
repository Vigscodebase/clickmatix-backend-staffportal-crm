const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const path = require('path');
const { logToFile } = require('./logger');

let dbPromise = null;

async function openDb() {
    if (!dbPromise) {
        logToFile('[DB] FIRST OPEN: Initializing database promise...');
        dbPromise = open({
            filename: path.join(__dirname, 'database.sqlite'),
            driver: sqlite3.Database
        }).then(async (db) => {
            logToFile('[DB] CONFIGURE: Setting performance PRAGMAs...');
            await db.exec('PRAGMA journal_mode = WAL');
            await db.configure('busyTimeout', 10000);

            // Auto-migration for am_head_id
            try {
                const cols = await db.all("PRAGMA table_info(clients)");
                if (!cols.find(c => c.name === 'am_head_id')) {
                    logToFile('[DB] MIGRATE: Adding am_head_id column...');
                    await db.exec('ALTER TABLE clients ADD COLUMN am_head_id INTEGER REFERENCES users(id)');
                    logToFile('[DB] MIGRATE: Success.');
                }
            } catch (e) {
                logToFile(`[DB] MIGRATE ERROR: ${e.message}`);
            }

            logToFile('[DB] CONFIGURE: Database initialized and ready.');
            return db;
        }).catch(err => {
            logToFile(`[DB] ERROR: Failed to open database: ${err.message}`);
            dbPromise = null;
            throw err;
        });
    }
    return dbPromise;
}

module.exports = openDb;
