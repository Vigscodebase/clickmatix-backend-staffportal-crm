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

            // --- THIS IS THE NEW MIGRATION SYSTEM ---
            try {
                //logToFile('[DB] MIGRATE: Checking for pending migrations...');
                // This command automatically looks inside your "migrations" folder
                // and runs 001, 002, 003, etc., in order.
                // await db.migrate({
                //     migrationsPath: path.join(__dirname, 'migrations')
                // });
                //logToFile('[DB] MIGRATE: Database schema is up to date.');
            } catch (migrationError) {
                //logToFile(`[DB] MIGRATE ERROR: ${migrationError.message}`);
                //console.error("Migration Error:", migrationError);
            }
            // ----------------------------------------

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