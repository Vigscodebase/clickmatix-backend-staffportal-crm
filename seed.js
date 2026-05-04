const fs = require('fs');
const csv = require('csv-parser');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');
const path = require('path');

async function seed() {
  const db = await open({
    filename: path.join(__dirname, 'database.sqlite'),
    driver: sqlite3.Database
  });

  // Initialize Schema
  await db.exec(`
    DROP TABLE IF EXISTS invoices;
    DROP TABLE IF EXISTS services;
    DROP TABLE IF EXISTS clients;
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS notifications;

    CREATE TABLE users (
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
      avatar_url TEXT
    );

    CREATE TABLE clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT,
      phone TEXT,
      domain TEXT,
      account_manager_id INTEGER,
      marketing_manager_id INTEGER,
      dev_manager_id INTEGER,
      am_head_id INTEGER,
      status TEXT DEFAULT 'Active',
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

    CREATE TABLE services (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      monthly_fee REAL DEFAULT 0,
      ad_spend REAL DEFAULT 0,
      tl_id INTEGER,
      status TEXT DEFAULT 'Active',
      status_color TEXT DEFAULT 'Green',
      revenue_type TEXT DEFAULT 'Recurring',
      revenue_month TEXT,
      FOREIGN KEY(client_id) REFERENCES clients(id)
    );

    CREATE TABLE invoices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      amount REAL NOT NULL,
      status TEXT DEFAULT 'Pending',
      month TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(client_id) REFERENCES clients(id)
    );

    CREATE TABLE notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      message TEXT NOT NULL,
      type TEXT,
      is_read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  const hashedPassword = bcrypt.hashSync('password123', 10);

  // Create Default Admin
  await db.run('INSERT INTO users (name, email, password, role, department, can_add, can_edit, can_delete) VALUES (?, ?, ?, ?, ?, 1, 1, 1)',
    'System Admin', 'admin@clickmatix.com', hashedPassword, 'super_admin', 'Management');

  // Cache users to avoid duplicates
  const userCache = {}; // email -> id

  async function getUserId(name, department = 'Operations') {
    if (!name || name === 'NA') return null;
    const email = `${name.toLowerCase().replace(/\s/g, '.')}@clickmatix.com`;

    if (userCache[email]) return userCache[email];

    let user = await db.get('SELECT id FROM users WHERE email = ?', email);
    if (!user) {
      const result = await db.run('INSERT INTO users (name, email, password, role, department) VALUES (?, ?, ?, ?, ?)',
        name, email, hashedPassword, 'staff', department);
      user = { id: result.lastID };
    }
    userCache[email] = user.id;
    return user.id;
  }

  function parseCurrency(str) {
    if (!str || str === 'NA') return 0;
    return parseFloat(str.replace(/[$,]/g, '')) || 0;
  }

  const servicesMap = [
    { type: 'SEO', feeCol: 'SEO ', tlCol: 'SEO TL', statusCol: 'Traffic Light SEO' },
    { type: 'G-ADS', feeCol: 'G-ads Managemen', spendCol: 'Monthly Ad spent g-ads', tlCol: 'G-ads TL', statusCol: 'Traffic Light G-ads' },
    { type: 'META', feeCol: 'Meta Management', spendCol: 'Monthly ads spent meta', tlCol: 'Meta TL', statusCol: 'Traffic Light Meta' },
    { type: 'EMAIL', feeCol: 'Email Mark', tlCol: 'Em TL', statusCol: 'Traffic Light EM' },
    { type: 'SMM', feeCol: 'SMM', tlCol: 'SMM TL', statusCol: 'Traffic Light SMM' }
  ];

  const results = [];

  if (!fs.existsSync('data.csv')) {
    console.log('No data.csv found, seeding dummy data only.');
    // Get the admin user ID specifically to assign as AM
    const admin = await db.get('SELECT id FROM users WHERE email = ?', 'admin@clickmatix.com');
    const adminId = admin ? admin.id : 1;

    // Add a dummy client if no CSV
    await db.run('INSERT INTO clients (name, email, domain, status, agreement_status, invoice_status, account_manager_id, marketing_manager_id, dev_manager_id, recurring_day) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'Demo Client', 'demo@client.com', 'demo.com', 'Active', 'Signed', 'Paid', adminId, adminId, adminId, 1);

    await db.run('INSERT INTO services (client_id, type, monthly_fee, status, revenue_type) VALUES (1, "SEO", 1500, "Active", "Recurring")');
    await db.run('INSERT INTO services (client_id, type, monthly_fee, status, revenue_type) VALUES (1, "G-ADS", 2500, "Active", "Recurring")');
    await db.run('INSERT INTO invoices (client_id, amount, status, month) VALUES (1, 4000, "Paid", "2026-01")');
    await db.run('INSERT INTO invoices (client_id, amount, status, month) VALUES (1, 4000, "Pending", "2026-02")');
    await db.close();
    return;
  }

  fs.createReadStream('data.csv')
    .pipe(csv())
    .on('data', (data) => results.push(data))
    .on('end', async () => {
      console.log('Processing CSV rows...');
      let clientCount = 0;
      for (const row of results) {
        const clientName = row['Client Name'];
        if (!clientName) continue;

        try {
          const amId = await getUserId(row['Account Manager'], 'Sales');
          const mmId = await getUserId(row['Marketing Manager'], 'Marketing');
          const dmId = await getUserId(row['Dev Manager'], 'Development');

          const clientEmail = row['Email Address'] || `${clientName.toLowerCase().replace(/\s/g, '')}@client.com`;
          const clientRes = await db.run(`
            INSERT INTO clients (name, email, phone, domain, account_manager_id, marketing_manager_id, dev_manager_id, status, agreement_status, invoice_status, onboarding_by, onboarding_date, onboarding_pdf_url, recurring_day, contract_end_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `, clientName, clientEmail, row['Phone Number'], row['Domain'], amId, mmId, dmId,
            row['Account Status'] || 'Active', 'Signed', 'Paid', amId, row['Onboarding Date'], null, 1, row['Contract End Date']);

          const clientId = clientRes.lastID;
          clientCount++;

          // 3. Create Services
          for (const svc of servicesMap) {
            const fee = parseCurrency(row[svc.feeCol]);
            const spend = svc.spendCol ? parseCurrency(row[svc.spendCol]) : 0;
            const tlName = row[svc.tlCol];

            if (fee > 0 || (tlName && tlName !== 'NA')) {
              const tlId = await getUserId(tlName);
              let status = (row[svc.statusCol] || 'Active').trim();
              if (status.toLowerCase().includes('green')) status = 'Active';
              else if (status.toLowerCase().includes('yellow')) status = 'Pause';
              else if (status.toLowerCase().includes('red')) status = 'Hold';
              else status = 'Active'; // Default to active if unknown

              // More realistic One-off vs Recurring distribution
              const revenueType = Math.random() > 0.85 ? 'One-off' : 'Recurring';
              const revenueMonth = '2026-01'; // Default month for demo data

              await db.run(`
                INSERT INTO services (client_id, type, monthly_fee, ad_spend, tl_id, status, revenue_type, revenue_month)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
              `, clientId, svc.type, fee, spend, tlId, status, revenueType, revenueMonth);
            }
          }

          // Add some dummy invoices
          if (clientCount % 2 === 0) {
            await db.run('INSERT INTO invoices (client_id, amount, status, month) VALUES (?, ?, ?, ?)',
              clientId, 2000, 'Paid', '2026-01');
          }
          if (clientCount % 3 === 0) {
            await db.run('INSERT INTO invoices (client_id, amount, status, month) VALUES (?, ?, ?, ?)',
              clientId, 3500, 'Pending', '2026-01');
          }

        } catch (err) {
          console.error('Error processing row:', clientName, err);
        }
      }
      console.log('Database seeded successfully!');
      await db.close();
    });
}

seed().catch(console.error);
