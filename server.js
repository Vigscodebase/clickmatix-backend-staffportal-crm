const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const openDb = require('./db');
const { logToFile } = require('./logger');

const app = express();
app.use(cors());
// app.use(express.json());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ limit: '5mb', extended: true }));

// Request logger middleware
app.use((req, res, next) => {
    const start = Date.now();
    const route = `${req.method} ${req.originalUrl}`;
    logToFile(`[API] START ${route}`);

    res.on('finish', () => {
        const duration = Date.now() - start;
        const msg = `[API] END   ${route} - ${res.statusCode} (${duration}ms)`;
        logToFile(msg);
    });
    next();
});

const SECRET_KEY = process.env.JWT_SECRET || 'supersecretkey';

// Middleware to authenticate token
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

const parseId = (id) => {
    if (id === undefined || id === null || id === "" || id === "null") return null;
    const parsed = parseInt(id, 10);
    return isNaN(parsed) ? null : parsed;
};

// Login Route
app.post('/api/login', async (req, res) => {
    const db = await openDb();
    const { email, password } = req.body;
    const user = await db.get('SELECT * FROM users WHERE email = ?', email);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    let permissions = [];
    try {
        permissions = user.permissions ? JSON.parse(user.permissions) : [];
    } catch (e) {
        permissions = [];
    }

    const token = jwt.sign({
        id: user.id,
        role: user.role,
        name: user.name,
        can_add: user.can_add,
        can_edit: user.can_edit,
        can_delete: user.can_delete,
        permissions: permissions
    }, SECRET_KEY, { expiresIn: '8h' });

    res.json({
        token, user: {
            id: user.id,
            name: user.name,
            role: user.role,
            email: user.email,
            department: user.department,
            can_add: user.can_add,
            can_edit: user.can_edit,
            can_delete: user.can_delete,
            permissions: permissions,
            location: user.location,
            avatar_url: user.avatar_url
        }
    });
});

const wsClients = new Map();

// Helper for Notifications (Updated to push WebSockets instantly)
const createNotification = async (userIds, message, type = 'info') => {
    const db = await openDb();
    const ids = Array.isArray(userIds) ? userIds : [userIds];
    for (const id of ids) {
        if (id) {
            // 1. Save to Database
            await db.run('INSERT INTO notifications (user_id, message, type) VALUES (?, ?, ?)', id, message, type);

            // 2. Instantly Push to Connected Client via WebSocket
            const userSockets = wsClients.get(id);
            if (userSockets) {
                for (const ws of userSockets) {
                    if (ws.readyState === 1) { // 1 = OPEN
                        ws.send(JSON.stringify({ event: 'new_notification' }));
                    }
                }
            }
        }
    }
};

// Notification Routes
app.get('/api/notifications', authenticate, async (req, res) => {
    const db = await openDb();
    const notifications = await db.all('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20', req.user.id);
    res.json({ notifications });
});

app.patch('/api/notifications/:id/read', authenticate, async (req, res) => {
    const db = await openDb();
    await db.run('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?', req.params.id, req.user.id);
    res.json({ success: true });
});

// Dashboard Data Route
app.get('/api/dashboard', authenticate, async (req, res) => {
    try {
        const db = await openDb();
        const { id, role, permissions } = req.user;
        const month = (req.query.month && req.query.month !== 'undefined' && req.query.month !== 'null') ? req.query.month : new Date().toISOString().slice(0, 7);
        const view = req.query.view || 'team';
        const hasFullAccess = ['super_admin', 'admin', 'sales', 'finance', 'am_head'].includes(role) || permissions?.includes('view_all_clients');

        await db.run(`UPDATE clients SET onboarding_date = date('now') WHERE onboarding_date = '' OR onboarding_date IS NULL`);

        const triggerNotifications = async () => {
            try {
                const today = new Date();
                const currentMonthStr = today.toISOString().slice(0, 7);
                const ldb = await openDb();
                const currentMonth = String(today.getMonth() + 1).padStart(2, '0'); // 01-12
                const currentYear = today.getFullYear();

                // Target day calculation (Exactly 7 days out)
                const futureDate = new Date();
                futureDate.setDate(today.getDate() + 7);
                const targetDay = futureDate.getDate();

                // Fetch clients whose invoice due day lands exactly on the target day
                const clientsToNotify = await ldb.all(
                    `SELECT * FROM clients WHERE CAST(recurring_day AS INTEGER) = ?`,
                    [targetDay]
                );

                for (const c of clientsToNotify) {
                    // OPTIMIZED: Calculates the sum total of all active services for this client
                    const serviceFeeResult = await ldb.get(
                        `SELECT COALESCE(SUM(monthly_fee), 0) as totalFee FROM services WHERE client_id = ? AND status = 'Active'`,
                        [c.id]
                    );
                    const monthlyfee = serviceFeeResult ? serviceFeeResult.totalFee : 0;

                    // Notification message layout template (without extra dollar prefix signs)
                    const notificationMessage = `The client ${c.name} payment of $${monthlyfee} is due on ${c.recurring_day}-${currentMonth}-${currentYear}`;

                    // Deduplication verification check
                    const alreadyNotified = await ldb.get(`
                SELECT 1 FROM notifications 
                WHERE message = ? AND created_at LIKE ? LIMIT 1
            `, [notificationMessage, `${currentMonthStr}%`]);

                    if (!alreadyNotified) {
                        const managerIds = [];

                        // Super Admin, Admin, and Head of Account Managers receive all notifications
                        const globalManagers = await ldb.all(
                            'SELECT id FROM users WHERE role IN ("super_admin", "admin", "am_head")'
                        );
                        globalManagers.forEach(m => managerIds.push(m.id));

                        // Account Manager user role receives only their assigned clients
                        if (c.account_manager_id) {
                            managerIds.push(c.account_manager_id);
                        }

                        const finalRecipientIds = [...new Set(managerIds.filter(Boolean))];

                        // Dispatch notification
                        await createNotification(finalRecipientIds, notificationMessage, 'payment');
                    }
                }
            } catch (notifyErr) {
                console.error("Notification trigger failed:", notifyErr);
            }
        };
        triggerNotifications();

        // --- Filtering Logic ---
        let clientFilter = '';
        let params = [];

        if (view === 'mine') {
            if (role === 'marketing_manager') {
                // MM: Only see clients where they are the assigned Marketing Manager
                clientFilter = `WHERE EXISTS (SELECT 1 FROM services s2 WHERE s2.client_id = c.id AND s2.tl_id = ?)`;
                params = [id];
            } else if (role === 'dev_manager') {
                // DM: Only see clients where they are the assigned Dev  Manager
                clientFilter = `WHERE EXISTS (SELECT 1 FROM services s2 WHERE s2.client_id = c.id AND s2.tl_id = ?)`;
                params = [id];
            } else if (role === 'am_head') {
                clientFilter = `WHERE c.account_manager_id = ?`;
                params = [id];
            }
            else if (role === 'sales') {
                clientFilter = `WHERE c.onboarding_by = ?`;
                params = [id];
            }
        } else if (view === 'team' && role === 'marketing_manager') {
            clientFilter = `WHERE c.marketing_manager_id = ?`;
            params = [id];
        }
        else if (view === 'team' && role === 'dev_manager') {
            clientFilter = `WHERE c.dev_manager_id = ?`;
            params = [id];
        }
        else if (view === 'team' && role === 'am_head') {
            clientFilter = `WHERE c.am_head_id = ?`;
            params = [id];
        }
        else if (view === 'team' && role === 'account_manager') {
            clientFilter = `WHERE c.account_manager_id = ?`;
            params = [id];
        } else {
            // Team View: DO NOT TOUCH - Left exactly as it was
            clientFilter = hasFullAccess ? '' : `WHERE EXISTS (SELECT 1 FROM services s2 WHERE s2.client_id = c.id AND s2.tl_id = ?)`;
            params = hasFullAccess ? [] : [id];
        }

        const privilegedRoles = ['super_admin', 'admin', 'finance', 'sales'];
        if (!privilegedRoles.includes(role) && !permissions?.includes('view_all_clients')) {
            clientFilter += (clientFilter ? ' AND ' : ' WHERE ') + "c.agreement_status = 'Signed' AND c.invoice_status = 'Paid'";
        }

        const joiner = clientFilter ? ' AND ' : ' WHERE ';

        // --- Statistics Calculations ---
        const stats = { totalMRR: 0, oneOffRevenue: 0, activeAccounts: 0, activeServices: 0, pendingInvoices: 0, paidInvoices: 0, lostAccounts: 0 };
        const mrrRes = await db.get(`SELECT COALESCE(SUM(s.monthly_fee), 0) as total FROM services s JOIN clients c ON s.client_id = c.id ${clientFilter} ${joiner} s.revenue_type = 'Recurring' AND s.status = 'Active'`, params);
        stats.totalMRR = mrrRes?.total || 0;
        console.log(`SELECT COALESCE(SUM(s.monthly_fee), 0) as total FROM services s JOIN clients c ON s.client_id = c.id ${clientFilter} ${joiner} s.revenue_type = 'Recurring' AND s.status = 'Active'`)

        const isGlobalViewer = ['super_admin', 'admin', 'sales', 'finance', 'am_head'].includes(role) || permissions?.includes('view_all_clients');
        const lostQuery = isGlobalViewer
            ? `SELECT COUNT(DISTINCT c.id) as total FROM clients c WHERE EXISTS (SELECT 1 FROM services s2 WHERE s2.client_id = c.id AND (s2.status_color = 'Red' OR s2.status IN ('Hold', 'Pause')))`
            : `SELECT COUNT(DISTINCT c.id) as total FROM clients c ${clientFilter} ${joiner} (EXISTS (SELECT 1 FROM services s2 WHERE s2.client_id = c.id AND (s2.status_color = 'Red' OR s2.status IN ('Hold', 'Pause'))))`;
        // const lostRes = await db.get(lostQuery, isGlobalViewer ? [] : params);
        const lostRes = await db.get(`SELECT COUNT(*) as total FROM lost_clients`);
        stats.lostAccounts = lostRes?.total || 0;

        const accCount = await db.get(`SELECT COUNT(DISTINCT c.id) as count FROM clients c ${clientFilter} ${joiner} c.status = 'Active'`, params);
        stats.activeAccounts = accCount?.count || 0;

        // const svcCount = await db.get(`SELECT COUNT(*) as count FROM services s JOIN clients c ON s.client_id = c.id ${clientFilter} ${joiner} s.status = 'Active'`, params);
        // stats.activeServices = svcCount?.count || 0;

        // AFTER — seo_specialist / ads_specialist: count only their own assigned services
        let svcCount;
        if (role === 'seo_specialist' || role === 'ads_specialist') {
            svcCount = await db.get(
                `SELECT COUNT(*) as count FROM services s WHERE s.tl_id = ? AND s.status = 'Active'`,
                [id]
            );
        } else {
            svcCount = await db.get(
                `SELECT COUNT(*) as count FROM services s JOIN clients c ON s.client_id = c.id ${clientFilter} ${joiner} s.status = 'Active'`,
                params
            );
        }
        stats.activeServices = svcCount?.count || 0;

        const oneOffRes = await db.get(`SELECT COALESCE(SUM(s.monthly_fee), 0) as total FROM services s JOIN clients c ON s.client_id = c.id ${clientFilter} ${joiner} s.revenue_type = 'One-off' AND s.revenue_month LIKE ?`, [...params, month + '%']);
        stats.oneOffRevenue = oneOffRes?.total || 0;

        const invoiceRes = await db.all(`SELECT i.status, COALESCE(SUM(i.amount), 0) as total, COUNT(*) as count FROM invoices i JOIN clients c ON i.client_id = c.id ${clientFilter} ${joiner} i.month LIKE ? GROUP BY i.status`, [...params, month + '%']);
        invoiceRes.forEach(r => {
            if (r.status === 'Paid') { stats.paidInvoices = r.total; stats.numPaidInvoices = r.count; }
            else if (r.status === 'Pending') { stats.pendingInvoices = r.total; stats.numPendingInvoices = r.count; }
        });

        // --- Lists (View-Aware) ---
        const serviceDistribution = await db.all(`SELECT s.type, SUM(s.monthly_fee) as revenue, COUNT(DISTINCT s.client_id) as active_accounts FROM services s JOIN clients c ON s.client_id = c.id ${clientFilter} ${joiner} s.status = 'Active' GROUP BY s.type ORDER BY revenue DESC`, params);
        //const amTable = await db.all(`SELECT COALESCE(u.name, 'Unassigned') as name, COUNT(DISTINCT c.id) as num_accounts, COALESCE(SUM(s.monthly_fee), 0) as revenue FROM clients c LEFT JOIN users u ON c.account_manager_id = u.id LEFT JOIN services s ON s.client_id = c.id AND s.status = 'Active' ${clientFilter} ${joiner} c.status = 'Active' GROUP BY c.account_manager_id ${view === 'mine' ? "HAVING COALESCE(u.name, 'Unassigned') != 'Unassigned'" : ""} ORDER BY revenue DESC`, params);
        // 1. Define the specific Join Condition
        let serviceJoinCondition = "ON s.client_id = c.id AND s.status = 'Active'";
        // 2. Apply logic only for marketing_manager in 'Mine' view
        if (view === 'mine' && (role === 'marketing_manager' || role === 'dev_manager')) {
            serviceJoinCondition = `ON s.client_id = c.id AND s.status = 'Active' AND s.tl_id = ${id}`;
        }
        // 3. Use the dynamic serviceJoinCondition in the query
        const groupCol = (role === 'marketing_manager') ? 'c.marketing_manager_id' :
            (role === 'dev_manager' && view === 'mine') ? 's.tl_id' :
                (role === 'dev_manager') ? 'c.dev_manager_id' : 'c.account_manager_id';

        const joinClause = (role === 'dev_manager' && view === 'mine')
            ? `LEFT JOIN services s ${serviceJoinCondition} LEFT JOIN users u ON s.tl_id = u.id`
            : `LEFT JOIN users u ON ${groupCol} = u.id LEFT JOIN services s ${serviceJoinCondition}`;

        const amTable = await db.all(`
    SELECT COALESCE(u.name, 'Unassigned') as name, 
           COUNT(DISTINCT c.id) as num_accounts, 
           COALESCE(SUM(s.monthly_fee), 0) as revenue 
    FROM clients c 
    LEFT JOIN services s ${serviceJoinCondition}
    LEFT JOIN users u ON ${groupCol} = u.id 
    ${clientFilter} ${joiner} c.status = 'Active' 
    GROUP BY ${groupCol} 
    ${view === 'mine' ? "HAVING COALESCE(u.name, 'Unassigned') != 'Unassigned'" : ""} 
    ORDER BY revenue DESC
`, params);

        const pendingReviewClients = await db.all(`SELECT id, name, agreement_status, invoice_status, onboarding_date FROM clients c ${clientFilter} ${clientFilter ? 'AND' : 'WHERE'} (agreement_status != 'Signed' OR invoice_status != 'Paid') ORDER BY onboarding_date DESC LIMIT 10`, params);
        const pendingAssignmentClients = await db.all(`SELECT id, name, marketing_manager_id, dev_manager_id, am_head_id, account_manager_id FROM clients c ${clientFilter} ${clientFilter ? 'AND' : 'WHERE'} c.status = 'Active' AND (account_manager_id IS NULL OR marketing_manager_id IS NULL OR dev_manager_id IS NULL OR EXISTS (SELECT 1 FROM services s WHERE s.client_id = c.id AND s.tl_id IS NULL AND s.status = 'Active')) LIMIT 10`, params);
        const pendingOnboardingClients = await db.all(`SELECT id, name, onboarding_date, onboarding_pdf_url FROM clients c ${clientFilter} ${clientFilter ? 'AND' : 'WHERE'} c.account_manager_id = ? AND (onboarding_pdf_url IS NULL OR onboarding_pdf_url = '') LIMIT 10`, [...params, id]);

        res.json({ stats, serviceDistribution, accountManagers: amTable, pendingReviewClients, pendingAssignmentClients, pendingOnboardingClients });
    } catch (err) {
        console.error("Dashboard error:", err);
        res.status(500).json({ message: 'Failed to fetch dashboard data', error: err.message });
    }
});

const isAdmin = (req, res, next) => {
    const { role, permissions } = req.user;
    const isPrivileged = role === 'super_admin' || role === 'admin' || role === 'am_head' || permissions?.includes('manage_staff');

    if (!isPrivileged) {
        return res.status(403).json({ message: 'Forbidden: Management access required' });
    }
    next();
};

app.get('/api/users', authenticate, isAdmin, async (req, res) => {
    const db = await openDb();
    const users = await db.all('SELECT id, name, email, role, department, can_add, can_edit, can_delete, permissions FROM users');
    res.json({ users });
});

app.get('/api/staff', authenticate, async (req, res) => {
    const db = await openDb();
    const users = await db.all('SELECT id, name, role, department FROM users');
    res.json({ users });
});

app.post('/api/users', authenticate, isAdmin, async (req, res) => {
    const db = await openDb();
    const { name, email, password, role, department, can_add, can_edit, can_delete, permissions } = req.body;

    if (req.user.role === 'am_head' && role !== 'account_manager') {
        return res.status(403).json({ message: 'AM Head can only create Account Manager roles' });
    }

    const hashedPassword = bcrypt.hashSync(password || 'password123', 10);

    try {
        const result = await db.run(
            'INSERT INTO users (name, email, password, role, department, can_add, can_edit, can_delete, permissions, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime("now"))',
            name, email, hashedPassword, role, department, can_add || 0, can_edit || 0, can_delete || 0, permissions || '[]'
        );
        res.status(201).json({ id: result.lastID, name, email, role, department });
    } catch (err) {
        res.status(400).json({ message: 'User already exists' });
    }
});

app.put('/api/users/:id', authenticate, isAdmin, async (req, res) => {
    const db = await openDb();
    const { id } = req.params;
    const { name, email, role, department, can_add, can_edit, can_delete, permissions, password } = req.body;

    if (req.user.role === 'am_head' && role !== 'account_manager') {
        return res.status(403).json({ message: 'AM Head can only edit Account Manager roles' });
    }

    if (password) {
        const hashedPassword = bcrypt.hashSync(password, 10);
        await db.run(
            'UPDATE users SET name = ?, email = ?, role = ?, department = ?, can_add = ?, can_edit = ?, can_delete = ?, permissions = ?, password = ? WHERE id = ?',
            name, email, role, department, can_add || 0, can_edit || 0, can_delete || 0, permissions || '[]', hashedPassword, id
        );
    } else {
        await db.run(
            'UPDATE users SET name = ?, email = ?, role = ?, department = ?, can_add = ?, can_edit = ?, can_delete = ?, permissions = ? WHERE id = ?',
            name, email, role, department, can_add || 0, can_edit || 0, can_delete || 0, permissions || '[]', id
        );
    }

    if (parseInt(id) !== req.user.id) {
        await createNotification(parseInt(id), `Your profile and permissions were updated by an administrator.`, 'info');
    }

    res.json({ success: true });
});

app.delete('/api/clients/:id', authenticate, async (req, res) => {
    const db = await openDb();
    const { id } = req.params;

    try {
        // Start a transaction so we don't end up with data in the wrong place
        await db.run('BEGIN TRANSACTION');

        // 1. Fetch client data to copy
        const client = await db.get('SELECT * FROM clients WHERE id = ?', id);

        if (!client) {
            await db.run('ROLLBACK');
            return res.status(404).json({ message: 'Client not found' });
        }

        // 2. Copy client to lost_clients table
        // Ensure column names match exactly with your 005-add-lost-clients.sql schema
        await db.run(`
            INSERT INTO lost_clients (
                id, name, email, phone, domain, account_manager_id, marketing_manager_id, 
                dev_manager_id, am_head_id, team_leader_id, status, agreement_status, 
                invoice_status, onboarding_by, onboarding_date, onboarding_pdf_url, 
                recurring_day, contract_end_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            client.id, client.name, client.email, client.phone, client.domain,
            client.account_manager_id, client.marketing_manager_id, client.dev_manager_id,
            client.am_head_id, client.team_leader_id, client.status, client.agreement_status,
            client.invoice_status, client.onboarding_by, client.onboarding_date,
            client.onboarding_pdf_url, client.recurring_day, client.contract_end_date
        ]);

        // 3. Delete from the CLIENTS table (NOT users table)
        await db.run('DELETE FROM clients WHERE id = ?', id);

        // Commit the transaction
        await db.run('COMMIT');

        res.json({ success: true, message: 'Client archived to lost_clients and deleted successfully' });
    } catch (err) {
        // If anything fails, revert all changes
        await db.run('ROLLBACK');
        console.error("Delete client error:", err);
        res.status(500).json({ message: 'Failed to delete client', error: err.message });
    }
});

// Client Management - Add Client
app.post('/api/clients', authenticate, async (req, res) => {
    const { role } = req.user;
    const isPrivileged = ['super_admin', 'admin', 'sales', 'finance', 'am_head', 'account_manager'].includes(role);

    if (!req.user.can_add && !isPrivileged) {
        return res.status(403).json({ message: 'Forbidden: No permission to add clients' });
    }

    const db = await openDb();

    const {
        name, email, phone, domain, am_id, mm_id, dm_id, am_head_id,
        account_manager_id, marketing_manager_id, dev_manager_id, services,
        agreement_status, invoice_status
    } = req.body;

    if (services && Array.isArray(services)) {
        const types = services.map(s => s.type);
        const uniqueTypes = new Set(types);
        if (types.length !== uniqueTypes.size) {
            return res.status(400).json({ message: 'Duplicate services are not allowed.' });
        }
    }

    const final_am = parseId(am_id || account_manager_id);
    const final_mm = parseId(mm_id || marketing_manager_id);
    const final_dm = parseId(dm_id || dev_manager_id);
    const final_am_head = parseId(am_head_id);
    const onboarding_by = req.user.id;

    const canApproveFinance = ['super_admin', 'admin', 'finance'].includes(role) || req.user.permissions?.includes('approve_finance');

    let final_agreement = 'Pending';
    let final_invoice = 'Pending';

    if (canApproveFinance) {
        final_agreement = agreement_status || 'Pending';
        final_invoice = invoice_status || 'Pending';
    }

    const initialStatus = (final_agreement === 'Signed' && final_invoice === 'Paid') ? 'Active' : 'Pending';

    try {
        const clientRes = await db.run(`
            INSERT INTO clients (name, email, phone, domain, account_manager_id, marketing_manager_id, dev_manager_id, am_head_id, onboarding_date, agreement_status, invoice_status, onboarding_by, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, name, email, phone, domain, final_am, final_mm, final_dm, final_am_head, new Date().toISOString().split('T')[0], final_agreement, final_invoice, onboarding_by, initialStatus);

        const clientId = clientRes.lastID;

        if (services && Array.isArray(services)) {
            for (const svc of services) {
                const final_tl = parseId(svc.tl_id);
                await db.run(`
                    INSERT INTO services (client_id, type, monthly_fee, ad_spend, tl_id, status, status_color, revenue_type, revenue_month)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                `, clientId, svc.type, svc.fee || 0, svc.spend || 0, final_tl, 'Active', 'Green', svc.revenue_type || 'Recurring', svc.revenue_month || null);
            }
        }

        res.status(201).json({ id: clientId, name });

        if (final_agreement === 'Signed' && final_invoice === 'Paid') {
            const managers = await db.all('SELECT id FROM users WHERE role IN ("super_admin", "admin", "am_head", "sales")');
            const managerIds = managers.map(m => m.id);
            if (final_am) managerIds.push(final_am);
            if (final_mm) managerIds.push(final_mm);
            if (final_dm) managerIds.push(final_dm);

            await createNotification([...new Set(managerIds)], `New Client ${name} onboarded and verified by Finance.`, 'approval');
        } else {
            const financeUsers = await db.all('SELECT id FROM users WHERE role = "finance" OR role = "super_admin" OR role = "admin"');
            await createNotification(financeUsers.map(u => u.id), `New client onboarded: ${name}. Pending finance review.`, 'onboarding');
        }

    } catch (err) {
        res.status(500).json({ message: 'Failed to create client', error: err.message });
    }
});

app.get('/api/projects', authenticate, async (req, res) => {
    const db = await openDb();
    const { department, role, id } = req.user;

    let query = `
        SELECT s.*, c.name as client_name, c.domain as client_domain, 
               u_tl.name as tl_name, u_am.name as am_name,
               s.status_color
        FROM services s
        JOIN clients c ON s.client_id = c.id
        LEFT JOIN users u_tl ON s.tl_id = u_tl.id
        LEFT JOIN users u_am ON c.account_manager_id = u_am.id
    `;
    let filters = [];
    let params = [];

    const view = req.query.view || 'team';
    const isPrivileged = ['super_admin', 'admin', 'finance', 'am_head'].includes(role);

    // --- FILTERING LOGIC ---
    if (view === 'mine' && isPrivileged) {
        filters.push('(c.account_manager_id = ? OR c.marketing_manager_id = ? OR c.dev_manager_id = ? OR s.tl_id = ?)');
        params.push(id, id, id, id);
    } else if (role === 'finance' || role === 'am_head' || role === 'sales') {
        // Full View - No filters
    } else if (role !== 'super_admin' && role !== 'admin') {
        filters.push("c.agreement_status = 'Signed' AND c.invoice_status = 'Paid'");

        // --- SPECIFIC LOGIC FOR MANAGERS ---
        if (role === 'marketing_manager') {
            if (view === 'mine') {
                filters.push('s.tl_id = ?');
                params.push(id);
            } else {
                filters.push('c.marketing_manager_id = ?');
                params.push(id);
            }
        }
        else if (role === 'dev_manager') {
            if (view === 'mine') {
                // In Mine view, show projects where the Dev Manager is the TL
                filters.push('s.tl_id = ?');
                params.push(id);
            } else {
                // In Team view, show projects where the Dev Manager is the dev_manager_id
                filters.push('c.dev_manager_id = ?');
                params.push(id);
            }
        }
        // --- EXISTING DEPARTMENT LOGIC ---
        else if (department === 'SEO') {
            filters.push('s.type = "SEO"');
        } else if (department === 'Paid Ads') {
            filters.push('s.type IN ("G-ADS", "META")');
        } else if (department === 'Development') {
            filters.push('s.type = "Development"');
        } else if (department === 'Marketing') {
            filters.push('s.type IN ("SEO", "G-ADS", "META", "EMAIL", "SMM")');
        } else {
            filters.push('(c.account_manager_id = ? OR s.tl_id = ?)');
            params.push(id, id);
        }
    }

    if (filters.length > 0) {
        query += ' WHERE ' + filters.join(' AND ');
    }

    const projects = await db.all(query, params);
    res.json({ projects });
});

app.get('/api/clients', authenticate, async (req, res) => {
    const db = await openDb();
    const { role, id, permissions } = req.user;
    const canViewRevenue = ['super_admin', 'admin', 'finance', 'am_head'].includes(role) || permissions?.includes('view_revenue');
    const hasFullAccess = ['super_admin', 'sales', 'admin', 'finance', 'am_head'].includes(role) || permissions?.includes('view_all_clients');

    let query = `
        SELECT c.*, u.name as am_name,
               ${canViewRevenue ? "(SELECT SUM(monthly_fee) FROM services WHERE client_id = c.id AND revenue_type = 'Recurring' AND status = 'Active')" : "0"} as recurring_revenue,
               ${canViewRevenue ? "(SELECT SUM(monthly_fee) FROM services WHERE client_id = c.id AND revenue_type = 'One-off')" : "0"} as one_off_revenue
        FROM clients c
        LEFT JOIN users u ON c.account_manager_id = u.id
    `;
    let params = [];
    const view = req.query.view || 'team';

    // --- FILTERING LOGIC ---
    if (view === 'mine') {
        if (role === 'marketing_manager') {
            // MM: Filter by marketing_manager_id AND check for Active services where user is TL
            query += ` WHERE c.marketing_manager_id = ? 
                       AND EXISTS (SELECT 1 FROM services s WHERE s.client_id = c.id AND s.tl_id = ? AND s.status = 'Active')`;
            params = [id, id];
        } else if (role === 'dev_manager') {
            // DM: Only see clients where the user is the TL in an Active service
            query += ` WHERE c.status = 'Active'              -- add this if you want to exclude Pending clients
               AND EXISTS (
                   SELECT 1 FROM services s 
                   WHERE s.client_id = c.id AND s.tl_id = ? AND s.status = 'Active'
               )`;
            params = [id];
        } else if (role === 'sales') {
            query += ` WHERE c.onboarding_by = ?`;
            params = [id];
        } else if (role === 'account_manager') {
            query += ` WHERE c.account_manager_id = ? AND (c.agreement_status = 'Signed' AND c.invoice_status = 'Paid')`;
            params = [id];
        } else {
            // Default logic for other roles
            query += ` WHERE (c.account_manager_id = ? OR c.marketing_manager_id = ? OR c.dev_manager_id = ? OR c.onboarding_by = ?
                      OR EXISTS (SELECT 1 FROM services s2 WHERE s2.client_id = c.id AND s2.tl_id = ?))`;
            params = [id, id, id, id, id];
        }
    } else if (hasFullAccess) {
        // No WHERE clause, load everything.
    } else {
        // Fallback for non-mine view (Team View)
        // Note: The dev_manager_id assignment is already included here in the OR condition
        if (role === 'dev_manager') {
            // DM Team View: only clients assigned to this dev_manager
            query += ` WHERE c.dev_manager_id = ?`;
            params = [id];
        } else {
            query += ` WHERE (c.account_manager_id = ? OR c.marketing_manager_id = ? OR c.dev_manager_id = ? OR c.onboarding_by = ?
                      OR EXISTS (SELECT 1 FROM services s2 WHERE s2.client_id = c.id AND s2.tl_id = ?))`;
            params = [id, id, id, id, id];
            if (!hasFullAccess) {
                query += ` AND (c.agreement_status = 'Signed' AND c.invoice_status = 'Paid')`;
            }
        }
    }

    const clients = await db.all(query, params);

    // Fetch services for these clients
    if (clients.length > 0) {
        const clientIds = clients.map(c => c.id).filter(id => id != null);
        if (clientIds.length > 0) {
            const placeholders = clientIds.map(() => '?').join(',');
            const allServices = await db.all(`
                SELECT client_id, type 
                FROM services 
                WHERE client_id IN (${placeholders})
            `, clientIds);

            clients.forEach(client => {
                client.services = allServices.filter(s => Number(s.client_id) === Number(client.id));
            });
        }
    } else {
        clients.forEach(c => c.services = []);
    }

    res.json({ clients });
});

app.get('/api/clients/:id', authenticate, async (req, res) => {
    const { id } = req.params;
    try {
        const db = await openDb();
        const client = await db.get('SELECT * FROM clients WHERE id = ?', id);

        if (!client) {
            return res.status(404).json({ message: 'Client not found' });
        }

        const am = client.account_manager_id ? await db.get('SELECT name FROM users WHERE id = ?', client.account_manager_id) : null;
        const mm = client.marketing_manager_id ? await db.get('SELECT name FROM users WHERE id = ?', client.marketing_manager_id) : null;
        const dm = client.dev_manager_id ? await db.get('SELECT name FROM users WHERE id = ?', client.dev_manager_id) : null;
        const ah = client.am_head_id ? await db.get('SELECT name FROM users WHERE id = ?', client.am_head_id) : null;

        client.am_name = am?.name;
        client.mm_name = mm?.name;
        client.dm_name = dm?.name;
        client.am_head_name = ah?.name;

        const services = await db.all(`
            SELECT s.*, u.name as tl_name 
            FROM services s
            LEFT JOIN users u ON s.tl_id = u.id
            WHERE s.client_id = ?
        `, id);

        // Fetch custom WYSIWYG Notes
        const notes = await db.all(`
            SELECT n.*, u.name as created_by_name 
            FROM client_notes n
            LEFT JOIN users u ON n.created_by = u.id
            WHERE n.client_id = ?
            ORDER BY n.created_at DESC
        `, id);

        res.json({ client, services, notes });
    } catch (err) {
        res.status(500).json({ message: 'Internal server error', error: err.message });
    }
});

app.post('/api/clients/:id/notes', authenticate, async (req, res) => {
    const { role, id: userId } = req.user;
    if (role !== 'super_admin' && role !== 'admin' && role !== 'am_head') return res.status(403).json({ message: 'Forbidden' });

    const db = await openDb();
    try {
        await db.run('INSERT INTO client_notes (client_id, content, created_by, created_at) VALUES (?, ?, ?, datetime("now", "localtime"))', req.params.id, req.body.content, userId);

        const client = await db.get('SELECT name, account_manager_id, am_head_id FROM clients WHERE id = ?', req.params.id);
        if (client) {
            const notifyIds = [client.account_manager_id, client.am_head_id].filter(i => i && i != userId);
            if (notifyIds.length > 0) {
                await createNotification([...new Set(notifyIds)], `A new note was added to ${client.name} by ${req.user.name}.`, 'info');
            }
        }

        res.status(201).json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to add note' });
    }
});

app.put('/api/notes/:id', authenticate, async (req, res) => {
    const { role, id: userId } = req.user;
    if (role !== 'super_admin' && role !== 'admin' && role !== 'am_head') return res.status(403).json({ message: 'Forbidden' });

    const db = await openDb();
    try {
        const existingNote = await db.get('SELECT n.client_id, c.name, c.account_manager_id, c.am_head_id FROM client_notes n JOIN clients c ON n.client_id = c.id WHERE n.id = ?', req.params.id);

        await db.run('UPDATE client_notes SET content = ? WHERE id = ?', req.body.content, req.params.id);

        if (existingNote) {
            const notifyIds = [existingNote.account_manager_id, existingNote.am_head_id].filter(i => i && i != userId);
            if (notifyIds.length > 0) {
                await createNotification([...new Set(notifyIds)], `A note for ${existingNote.name} was updated by ${req.user.name}.`, 'info');
            }
        }

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to update note' });
    }
});

app.delete('/api/notes/:id', authenticate, async (req, res) => {
    const { role, id: userId } = req.user;
    if (role !== 'super_admin' && role !== 'admin' && role !== 'am_head') return res.status(403).json({ message: 'Forbidden' });

    const db = await openDb();
    try {
        const existingNote = await db.get('SELECT n.client_id, c.name, c.account_manager_id, c.am_head_id FROM client_notes n JOIN clients c ON n.client_id = c.id WHERE n.id = ?', req.params.id);

        await db.run('DELETE FROM client_notes WHERE id = ?', req.params.id);

        if (existingNote) {
            const notifyIds = [existingNote.account_manager_id, existingNote.am_head_id].filter(i => i && i != userId);
            if (notifyIds.length > 0) {
                await createNotification([...new Set(notifyIds)], `A note for ${existingNote.name} was deleted by ${req.user.name}.`, 'warning');
            }
        }

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to delete note' });
    }
});

app.put('/api/clients/:id', authenticate, async (req, res) => {
    const { role } = req.user;
    const isPrivileged = ['super_admin', 'admin', 'sales', 'finance', 'am_head', 'marketing_manager', 'dev_manager'].includes(role);

    if (!req.user.can_edit && !isPrivileged) {
        return res.status(403).json({ message: 'Forbidden: No permission to edit clients' });
    }

    const db = await openDb();
    const { id } = req.params;
    const { name, email, phone, domain, am_id, mm_id, dm_id, account_manager_id, marketing_manager_id, dev_manager_id, am_head_id, status } = req.body;

    const incoming_am = parseId(am_id || account_manager_id);
    const incoming_mm = parseId(mm_id || marketing_manager_id);
    const incoming_dm = parseId(dm_id || dev_manager_id);
    let final_am_head = parseId(am_head_id);

    try {
        const existing = await db.get('SELECT * FROM clients WHERE id = ?', id);
        if (!existing) return res.status(404).json({ message: 'Client not found' });

        let final_am = incoming_am;
        let final_mm = incoming_mm;
        let final_dm = incoming_dm;

        if (role === 'am_head') {
            final_mm = existing.marketing_manager_id;
            final_dm = existing.dev_manager_id;
        } else if (role === 'marketing_manager') {
            final_am = existing.account_manager_id;
            final_dm = existing.dev_manager_id;
        } else if (role === 'dev_manager') {
            final_am = existing.account_manager_id;
            final_mm = existing.marketing_manager_id;
        } else if (role === 'sales') {
            final_am = existing.account_manager_id;
            final_mm = existing.marketing_manager_id;
            final_dm = existing.dev_manager_id;
            final_am_head = existing.am_head_id;
        }

        await db.run(`
            UPDATE clients 
            SET name = ?, email = ?, phone = ?, domain = ?, account_manager_id = ?, marketing_manager_id = ?, dev_manager_id = ?, am_head_id = ?, status = ?
            WHERE id = ?
        `, name, email, phone, domain, final_am, final_mm, final_dm, final_am_head, status, id);

        // 1. Specific Assignment/Removal Notifications
        let specificNotified = new Set();
        const clientName = name || existing.name;

        const notifyAssignmentChange = async (roleName, finalId, existingId) => {
            if (finalId !== existingId) {
                if (finalId) {
                    await createNotification(finalId, `You have been assigned as the ${roleName} for ${clientName}`, 'info');
                    specificNotified.add(finalId);
                }
                if (existingId) {
                    await createNotification(existingId, `You have been removed as the ${roleName} for ${clientName}`, 'warning');
                    specificNotified.add(existingId);
                }
            }
        };

        await notifyAssignmentChange('Account Manager', final_am, existing.account_manager_id);
        await notifyAssignmentChange('Marketing Manager', final_mm, existing.marketing_manager_id);
        await notifyAssignmentChange('Dev Manager', final_dm, existing.dev_manager_id);
        await notifyAssignmentChange('AM Head', final_am_head, existing.am_head_id);

        // 2. Fetch Global Role IDs for General Update Notification
        const privilegedRoles = ["super_admin", "admin", "sales", "finance", "am_head"];
        const privilegedUsers = await db.all(`SELECT id FROM users WHERE role IN (${privilegedRoles.map(r => `'${r}'`).join(',')})`);
        const privilegedIds = privilegedUsers.map(u => u.id);

        // 3. Combine with current stakeholders
        const stakeholderIds = [existing.account_manager_id, existing.marketing_manager_id, existing.dev_manager_id, existing.am_head_id, final_am, final_mm, final_dm, final_am_head];

        // 4. Merge, Unique, and exclude current user + already specifically notified users
        const notifyIds = [...new Set([...privilegedIds, ...stakeholderIds])]
            .filter(i => i && i != req.user.id && !specificNotified.has(i));

        if (notifyIds.length > 0) {
            await createNotification(notifyIds, `Client details for ${clientName} have been updated.`, 'info');
        }

        res.json({ success: true });
    } catch (err) {
        logToFile(`[API] CLIENT UPDATE ERROR: ${err.message}`);
        res.status(500).json({ message: 'Failed to update client', error: err.message });
    }
});

app.patch('/api/clients/:id/finance', authenticate, async (req, res) => {
    const { role } = req.user;
    if (role !== 'super_admin' && role !== 'admin' && role !== 'finance') {
        return res.status(403).json({ message: 'Forbidden' });
    }

    const { id } = req.params;
    const updates = req.body;
    const db = await openDb();

    try {
        const client = await db.get('SELECT * FROM clients WHERE id = ?', id);
        if (!client) return res.status(404).json({ message: 'Client not found' });

        // Normalize string IDs to integers or nulls using the pre-existing utility function
        if (updates.hasOwnProperty('marketing_manager_id')) updates.marketing_manager_id = parseId(updates.marketing_manager_id);
        if (updates.hasOwnProperty('dev_manager_id')) updates.dev_manager_id = parseId(updates.dev_manager_id);
        if (updates.hasOwnProperty('am_head_id')) updates.am_head_id = parseId(updates.am_head_id);
        if (updates.hasOwnProperty('account_manager_id')) updates.account_manager_id = parseId(updates.account_manager_id);

        const agreementChangedToPending = updates.hasOwnProperty('agreement_status') && (updates.agreement_status === 'Pending' || updates.agreement_status === 'Review Required');
        const invoiceChangedToPending = updates.hasOwnProperty('invoice_status') && (updates.invoice_status === 'Pending' || updates.invoice_status === 'Review Required');

        // Helper to notify assignments/removals
        const notifyRoleChange = async (roleName, newId, oldId) => {
            const normalizedNew = newId !== null ? parseInt(newId, 10) : null;
            const normalizedOld = oldId !== null ? parseInt(oldId, 10) : null;

            if (normalizedNew !== normalizedOld) {
                if (normalizedNew) await createNotification(normalizedNew, `You have been assigned as the ${roleName} for ${client.name}.`, 'info');
                if (normalizedOld) await createNotification(normalizedOld, `You have been removed as the ${roleName} for ${client.name}.`, 'warning');
            }
        };

        if (agreementChangedToPending || invoiceChangedToPending) {
            // Notify removals because Finance is stripping roles
            await notifyRoleChange('Marketing Manager', null, client.marketing_manager_id);
            await notifyRoleChange('Dev Manager', null, client.dev_manager_id);
            await notifyRoleChange('AM Head', null, client.am_head_id);
            await notifyRoleChange('Account Manager', null, client.account_manager_id);

            updates.marketing_manager_id = null;
            updates.dev_manager_id = null;
            updates.am_head_id = null;
            updates.account_manager_id = null;
        } else {
            // Only evaluate and track explicit updates if the payload actually contains the specific keys
            if (updates.hasOwnProperty('marketing_manager_id')) {
                await notifyRoleChange('Marketing Manager', updates.marketing_manager_id, client.marketing_manager_id);
            }
            if (updates.hasOwnProperty('dev_manager_id')) {
                await notifyRoleChange('Dev Manager', updates.dev_manager_id, client.dev_manager_id);
            }
            if (updates.hasOwnProperty('am_head_id')) {
                await notifyRoleChange('AM Head', updates.am_head_id, client.am_head_id);
            }
            if (updates.hasOwnProperty('account_manager_id')) {
                await notifyRoleChange('Account Manager', updates.account_manager_id, client.account_manager_id);
            }
        }

        const allowedFields = [
            'agreement_status', 'invoice_status', 'marketing_manager_id',
            'dev_manager_id', 'am_head_id', 'account_manager_id', 'recurring_day', 'status'
        ];

        const setClauses = [];
        const params = [];

        allowedFields.forEach(field => {
            if (updates.hasOwnProperty(field)) {
                setClauses.push(`${field} = ?`);
                params.push(updates[field]);
            }
        });

        if (setClauses.length > 0) {
            params.push(id);
            await db.run(`UPDATE clients SET ${setClauses.join(', ')} WHERE id = ?`, params);
        }

        // =========================================================================
        // --- ACTIVE TRIGGER FOR RECURRING DAY CHANGES (2025/2026 ARCHITECTURE) ---
        // =========================================================================
        if (updates.hasOwnProperty('recurring_day')) {
            try {
                const today = new Date();
                const futureDate = new Date();
                futureDate.setDate(today.getDate() + 7);
                const targetDay = futureDate.getDate();
                const currentMonth = String(today.getMonth() + 1).padStart(2, '0');
                const currentYear = today.getFullYear();

                const newRecurringDay = parseInt(updates.recurring_day, 10);

                // Check if the modified day lands exactly 7 days from today
                if (newRecurringDay === targetDay) {
                    // 1. Calculate the dynamic sum total of all active services
                    const serviceFeeResult = await db.get(
                        `SELECT COALESCE(SUM(monthly_fee), 0) as totalFee FROM services WHERE client_id = ? AND status = 'Active'`,
                        [id]
                    );
                    const monthlyfee = serviceFeeResult ? serviceFeeResult.totalFee : 0;

                    // 2. Map notification template matching layout string requirements
                    const notificationMessage = `The client ${client.name} payment of $${monthlyfee} is due on ${newRecurringDay}-${currentMonth}-${currentYear}`;

                    const managerIds = [];

                    // 3. Super Admin, Admin, and Head of Account Managers get all notifications
                    const globalManagers = await db.all(
                        'SELECT id FROM users WHERE role IN ("super_admin", "admin", "am_head")'
                    );
                    globalManagers.forEach(m => managerIds.push(m.id));

                    // 4. Account Manager role gets notified only if assigned to this specific client
                    const currentAmId = updates.hasOwnProperty('account_manager_id') ? updates.account_manager_id : client.account_manager_id;
                    if (currentAmId) {
                        managerIds.push(parseInt(currentAmId, 10));
                    }

                    const finalRecipientIds = [...new Set(managerIds.filter(Boolean))];

                    // 5. Instantly dispatch without any deduplication blocks
                    await createNotification(finalRecipientIds, notificationMessage, 'payment');
                }
            } catch (notifyErr) {
                console.error("Active trigger notification failed:", notifyErr);
            }
        }
        // =========================================================================

        // --- GENERAL FINANCE NOTIFICATIONS ---
        const agreementChanged = updates.agreement_status !== undefined && updates.agreement_status !== client.agreement_status;
        const invoiceChanged = updates.invoice_status !== undefined && updates.invoice_status !== client.invoice_status;

        if (agreementChanged || invoiceChanged) {
            const notifyUsers = await db.all('SELECT id FROM users WHERE role IN ("sales", "super_admin", "admin", "am_head")');
            const notifyIds = notifyUsers.map(u => u.id);

            if (client.account_manager_id) notifyIds.push(client.account_manager_id);

            const uniqueNotifyIds = [...new Set(notifyIds)].filter(userId => userId !== req.user.id);

            let changeMsgs = [];
            if (agreementChanged) changeMsgs.push(`Agreement: ${updates.agreement_status}`);
            if (invoiceChanged) changeMsgs.push(`Invoice: ${updates.invoice_status}`);

            if (uniqueNotifyIds.length > 0) {
                await createNotification(uniqueNotifyIds, `Finance status updated for ${client.name} -> ${changeMsgs.join(' | ')}`, 'info');
            }
        }

        res.json({ success: true });
    } catch (err) {
        logToFile(`[API] FINANCE UPDATE ERROR: ${err.message}`);
        res.status(500).json({ message: 'Failed to update finance status', error: err.message });
    }
});

app.post('/api/services', authenticate, async (req, res) => {
    const { role } = req.user;
    const isPrivileged = ['super_admin', 'admin', 'sales', 'finance', 'marketing_manager', 'dev_manager'].includes(role);

    if (!req.user.can_edit && !isPrivileged) {
        return res.status(403).json({ message: 'Forbidden: No permission to add services' });
    }

    const { client_id, type, monthly_fee, ad_spend, tl_id, status, revenue_type, revenue_month } = req.body;

    if (role === 'marketing_manager' && type === 'Development') return res.status(403).json({ message: 'MM cannot add Development services' });
    if (role === 'dev_manager' && type !== 'Development') return res.status(403).json({ message: 'DM can only add Development services' });

    const db = await openDb();

    const existingService = await db.get('SELECT id FROM services WHERE client_id = ? AND type = ?', client_id, type);
    if (existingService) {
        return res.status(400).json({ message: `This client already has the ${type} service active.` });
    }

    let finalStatus = status || 'Active';
    let status_color = 'Green';
    if (finalStatus === 'Pause') status_color = 'Yellow';
    if (finalStatus === 'Hold') status_color = 'Red';

    const final_tl = parseId(tl_id);

    try {
        const result = await db.run(`
            INSERT INTO services (client_id, type, monthly_fee, ad_spend, tl_id, status, status_color, revenue_type, revenue_month)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, client_id, type, monthly_fee || 0, ad_spend || 0, final_tl, finalStatus, status_color, revenue_type || 'Recurring', revenue_month || null);

        const serviceId = result.lastID;

        const clientForSvc = await db.get('SELECT name, account_manager_id, am_head_id FROM clients WHERE id = ?', client_id);

        if (final_tl) {
            await createNotification(final_tl, `You have been assigned as the Team Lead for ${type} service for ${clientForSvc?.name || 'a client'}`, 'info');
        }

        if (clientForSvc) {
            const amIds = [clientForSvc.account_manager_id, clientForSvc.am_head_id].filter(i => i && i != req.user.id && i !== final_tl);
            if (amIds.length > 0) {
                await createNotification([...new Set(amIds)], `A new ${type} service was added to ${clientForSvc.name}.`, 'info');
            }
        }

        res.status(201).json({ id: serviceId });
    } catch (err) {
        res.status(500).json({ message: 'Failed to add service', error: err.message });
    }
});

app.put('/api/services/:id', authenticate, async (req, res) => {
    const { role } = req.user;
    const isPrivileged = ['super_admin', 'admin', 'sales', 'finance', 'marketing_manager', 'dev_manager'].includes(role);

    if (!req.user.can_edit && !isPrivileged) return res.status(403).json({ message: 'Forbidden: No permission to edit services' });

    const db = await openDb();
    const { id } = req.params;
    const { type, monthly_fee, ad_spend, tl_id, status, revenue_type, revenue_month } = req.body;

    if (role === 'marketing_manager' && type === 'Development') return res.status(403).json({ message: 'MM cannot manage Development services' });
    if (role === 'dev_manager' && type !== 'Development') return res.status(403).json({ message: 'DM can only manage Development services' });

    let status_color = 'Green';
    if (status === 'Pause') status_color = 'Yellow';
    if (status === 'Hold') status_color = 'Red';

    const final_tl = parseId(tl_id);

    try {
        const existing = await db.get('SELECT * FROM services WHERE id = ?', id);
        if (!existing) return res.status(404).json({ message: 'Service not found' });

        const clientForUpd = await db.get('SELECT name, account_manager_id, am_head_id FROM clients WHERE id = ?', existing.client_id);

        await db.run(`
            UPDATE services 
            SET type = ?, monthly_fee = ?, ad_spend = ?, tl_id = ?, status = ?, status_color = ?, revenue_type = ?, revenue_month = ?
            WHERE id = ?
        `, type, monthly_fee || 0, ad_spend || 0, final_tl, status, status_color, revenue_type, revenue_month, id);

        // --- TL Assignment and Removal Notifications ---
        if (final_tl !== existing.tl_id) {
            if (final_tl) {
                await createNotification(final_tl, `You have been assigned as the Team Lead for ${type || existing.type} service for ${clientForUpd?.name || 'a client'}`, 'info');
            }
            if (existing.tl_id) {
                await createNotification(existing.tl_id, `You have been removed as the Team Lead for ${type || existing.type} service for ${clientForUpd?.name || 'a client'}`, 'warning');
            }
        }

        // --- NOTIFY PRIVILEGED ROLES + CLIENT MANAGERS ---
        // 1. Get all IDs for the requested roles
        const privilegedUsers = await db.all('SELECT id FROM users WHERE role IN ("super_admin", "admin", "finance", "am_head")');
        const privilegedIds = privilegedUsers.map(u => u.id);

        // 2. Combine with client-specific stakeholders
        const allCandidates = [...privilegedIds, clientForUpd?.account_manager_id, clientForUpd?.am_head_id];

        // 3. Filter: Remove current user and avoid double-notifying the TL (who is handled above)
        const finalNotifyIds = [...new Set(allCandidates)].filter(i =>
            i && i != req.user.id && i !== final_tl && i !== existing.tl_id
        );
        console.log(finalNotifyIds)
        if (finalNotifyIds.length > 0) {
            await createNotification(finalNotifyIds, `Service details for ${type || existing.type} (${clientForUpd?.name || 'Client'}) have been updated.`, 'info');
        }

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to update service', error: err.message });
    }
});

app.patch('/api/clients/:id/assign', authenticate, async (req, res) => {
    const { role, id: userId } = req.user;
    const { id } = req.params;
    const { account_manager_id, tl_id, service_type } = req.body;
    const db = await openDb();

    const client = await db.get('SELECT * FROM clients WHERE id = ?', id);
    if (!client) return res.status(404).json({ message: 'Client not found' });

    const isAMHead = role === 'am_head' || role === 'super_admin' || role === 'admin';
    const isMM = (role === 'marketing_manager' && client.marketing_manager_id === userId) || role === 'super_admin' || role === 'admin';
    const isDM = (role === 'dev_manager' && client.dev_manager_id === userId) || role === 'super_admin' || role === 'admin';

    try {
        if (account_manager_id !== undefined && isAMHead) {
            const finalAm = parseId(account_manager_id);
            await db.run('UPDATE clients SET account_manager_id = ? WHERE id = ?', finalAm, id);

            // --- NEW: Specific Removal on Patch ---
            if (finalAm !== client.account_manager_id) {
                if (finalAm) {
                    await createNotification(finalAm, `New account assigned: ${client.name}. Please start onboarding.`, 'assignment');
                }
                if (client.account_manager_id) {
                    await createNotification(client.account_manager_id, `You have been removed as the Account Manager for ${client.name}.`, 'warning');
                }
            }
        }

        if (tl_id !== undefined && service_type && (isMM || isDM)) {
            const finalTl = parseId(tl_id);
            const existingService = await db.get('SELECT tl_id FROM services WHERE client_id = ? AND type = ?', id, service_type);
            await db.run('UPDATE services SET tl_id = ? WHERE client_id = ? AND type = ?', finalTl, id, service_type);

            // --- NEW: Specific TL Removal on Patch ---
            if (existingService && finalTl !== existingService.tl_id) {
                if (finalTl) {
                    await createNotification(finalTl, `You have been assigned as TL for ${service_type} on client ${client.name}`, 'assignment');
                }
                if (existingService.tl_id) {
                    await createNotification(existingService.tl_id, `You have been removed as TL for ${service_type} on client ${client.name}`, 'warning');
                }
            }
        }

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to assign staff', error: err.message });
    }
});

app.patch('/api/clients/:id/onboarding', authenticate, async (req, res) => {
    const { id } = req.params;
    const { onboarding_date, onboarding_pdf_url } = req.body;
    const db = await openDb();

    try {
        await db.run('UPDATE clients SET onboarding_date = ?, onboarding_pdf_url = ? WHERE id = ?',
            onboarding_date, onboarding_pdf_url, id);

        // Fetch client details including the assigned Account Manager
        const client = await db.get('SELECT name, account_manager_id FROM clients WHERE id = ?', id);

        // Fetch all users with the required roles
        const targetUsers = await db.all('SELECT id FROM users WHERE role IN ("super_admin", "admin", "am_head", "account_manager", "finance")');

        // Create an array of all IDs to notify
        let notifyIds = targetUsers.map(m => m.id);

        // Ensure the client's assigned account manager is in the list
        if (client.account_manager_id) {
            notifyIds.push(client.account_manager_id);
        }

        // Remove duplicates and exclude the user who triggered the update
        const uniqueNotifyIds = [...new Set(notifyIds)].filter(userId => userId != req.user.id);

        if (uniqueNotifyIds.length > 0) {
            await createNotification(uniqueNotifyIds, `Onboarding completed for ${client.name} on ${onboarding_date}`, 'onboarding');
        }

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to update onboarding info' });
    }
});

app.patch('/api/services/:id/status', authenticate, async (req, res) => {
    const db = await openDb();
    const { id } = req.params;
    let { status, status_color } = req.body;

    try {
        const existing = await db.get('SELECT s.*, c.name as client_name, c.account_manager_id, c.am_head_id FROM services s JOIN clients c ON s.client_id = c.id WHERE s.id = ?', id);
        if (!existing) return res.status(404).json({ message: 'Service not found' });

        if (status && !status_color) {
            if (status === 'Active') status_color = 'Green';
            if (status === 'Pause' || status === 'Review Required') status_color = 'Yellow';
            if (status === 'Hold' || status === 'Pending') status_color = 'Red';
        } else if (status_color && !status) {
            if (status_color === 'Green') status = 'Active';
            if (status_color === 'Yellow') status = 'Pause';
            if (status_color === 'Red') status = 'Hold';
        }

        if (status) await db.run('UPDATE services SET status = ? WHERE id = ?', status, id);
        if (status_color) await db.run('UPDATE services SET status_color = ? WHERE id = ?', status_color, id);

        // 1. Get IDs of all users with the requested privileged roles
        const privilegedUsers = await db.all('SELECT id FROM users WHERE role IN ("super_admin", "admin", "sales", "finance", "am_head")');
        const privilegedIds = privilegedUsers.map(u => u.id);

        // 2. Combine with client-specific stakeholders (TL, AM, AM Head)
        const allCandidates = [
            ...privilegedIds,
            existing.account_manager_id,
            existing.am_head_id,
            existing.tl_id
        ];

        // 3. Deduplicate and remove the user performing the action
        const finalNotifyIds = [...new Set(allCandidates)].filter(i => i && i != req.user.id);

        const isCritical = (status && ['Pause', 'Hold'].includes(status)) || (status_color && status_color === 'Red');

        if (finalNotifyIds.length > 0) {
            await createNotification(
                finalNotifyIds,
                `Status update for ${existing.client_name}: ${existing.type} is now ${status || existing.status} (${status_color || existing.status_color})`,
                isCritical ? 'warning' : 'info'
            );
        }

        res.json({ success: true, status, status_color });
    } catch (err) {
        logToFile(`[API] STATUS UPDATE ERROR: ${err.message}`);
        res.status(500).json({ message: 'Failed to update status' });
    }
});

app.get('/api/invoices', authenticate, async (req, res) => {
    const db = await openDb();
    const invoices = await db.all(`SELECT i.*, c.name as client_name FROM invoices i JOIN clients c ON i.client_id = c.id ORDER BY i.month DESC`);
    res.json({ invoices });
});

app.post('/api/invoices', authenticate, isAdmin, async (req, res) => {
    const db = await openDb();
    const { client_id, amount, status, month } = req.body;

    await db.run('INSERT INTO invoices (client_id, amount, status, month) VALUES (?, ?, ?, ?)', client_id, amount, status, month);

    const clientForInv = await db.get('SELECT name, account_manager_id FROM clients WHERE id = ?', client_id);
    const financeUsers = await db.all('SELECT id FROM users WHERE role = "finance" OR role = "super_admin"');

    const invNotifyIds = [...financeUsers.map(u => u.id), clientForInv?.account_manager_id].filter(i => i && i != req.user.id);
    if (invNotifyIds.length > 0) {
        await createNotification([...new Set(invNotifyIds)], `New invoice created for ${clientForInv?.name || 'Client'} (${month}) - Amount: $${amount}`, 'payment');
    }

    res.status(201).json({ success: true });
});

app.delete('/api/services/:id', authenticate, async (req, res) => {
    if (!req.user.can_edit && req.user.role !== 'super_admin' && req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
    const db = await openDb();
    try {
        const svcToDelete = await db.get('SELECT s.type, s.tl_id, c.name as client_name, c.account_manager_id, c.am_head_id FROM services s JOIN clients c ON s.client_id = c.id WHERE s.id = ?', req.params.id);

        await db.run('DELETE FROM services WHERE id = ?', req.params.id);

        if (svcToDelete) {
            const delNotifyIds = [svcToDelete.account_manager_id, svcToDelete.am_head_id, svcToDelete.tl_id].filter(i => i && i != req.user.id);
            if (delNotifyIds.length > 0) {
                await createNotification([...new Set(delNotifyIds)], `Service ${svcToDelete.type} for ${svcToDelete.client_name} was deleted.`, 'warning');
            }
        }

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to delete service', error: err.message });
    }
});

app.delete('/api/clients/:id', authenticate, async (req, res) => {
    if (!req.user.can_delete && req.user.role !== 'super_admin' && req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
    const db = await openDb();
    try {
        const cliToDelete = await db.get('SELECT * FROM clients WHERE id = ?', req.params.id);

        await db.run('DELETE FROM services WHERE client_id = ?', req.params.id);
        await db.run('DELETE FROM clients WHERE id = ?', req.params.id);

        if (cliToDelete) {
            const delCliIds = [cliToDelete.account_manager_id, cliToDelete.marketing_manager_id, cliToDelete.dev_manager_id, cliToDelete.am_head_id, cliToDelete.onboarding_by].filter(i => i && i != req.user.id);
            if (delCliIds.length > 0) {
                await createNotification([...new Set(delCliIds)], `Client ${cliToDelete.name} and all related services were deleted.`, 'warning');
            }
        }

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to delete client', error: err.message });
    }
});

app.get('/api/service-types', authenticate, async (req, res) => {
    try {
        const db = await openDb();
        const rows = await db.all("SELECT * FROM service_types ORDER BY id ASC");
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/service-types', authenticate, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name || name.trim() === '') return res.status(400).json({ error: "Service name is required" });

        const db = await openDb();
        const result = await db.run("INSERT INTO service_types (name) VALUES (?)", name.trim());
        const serviceName = name.trim();

        // --- NEW NOTIFICATION LOGIC ---
        // Fetch all users with the required roles
        const notifyUsers = await db.all(`
            SELECT id FROM users 
            WHERE role IN ("super_admin", "admin", "sales", "finance", "am_head")
        `);

        // Map to IDs and remove the current user (sender) from the list
        const notifyIds = notifyUsers.map(u => u.id).filter(id => id != req.user.id);

        if (notifyIds.length > 0) {
            await createNotification(
                notifyIds,
                `New service type '${serviceName}' has been added by ${req.user.name}.`,
                'info'
            );
        }
        // ------------------------------

        res.status(201).json({ id: result.lastID, name: serviceName });
    } catch (err) {
        if (err.message.includes("UNIQUE")) return res.status(400).json({ error: "Service already exists" });
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/profile', authenticate, async (req, res) => {
    const db = await openDb();
    try {
        const user = await db.get('SELECT * FROM users WHERE id = ?', req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        delete user.password;
        let permissions = [];
        try { permissions = user.permissions ? JSON.parse(user.permissions) : []; } catch (e) { permissions = []; }
        user.permissions = permissions;
        const freshToken = jwt.sign({
            id: user.id, role: user.role, name: user.name, can_add: user.can_add,
            can_edit: user.can_edit, can_delete: user.can_delete, permissions: permissions
        }, process.env.JWT_SECRET || 'supersecretkey', { expiresIn: '8h' });
        res.json({ user, token: freshToken });
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.put('/api/profile', authenticate, async (req, res) => {
    const db = await openDb();
    const { name, location, avatar_url, password } = req.body;
    try {
        if (password) {
            const hashedPassword = bcrypt.hashSync(password, 10);
            await db.run('UPDATE users SET name = ?, location = ?, avatar_url = ?, password = ? WHERE id = ?', name, location, avatar_url, hashedPassword, req.user.id);
        } else {
            await db.run('UPDATE users SET name = ?, location = ?, avatar_url = ? WHERE id = ?', name, location, avatar_url, req.user.id);
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to update profile' });
    }
});

app.put('/api/service-types/:id', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        const { name } = req.body;

        // Validation Check
        if (!name || name.trim() === '') {
            return res.status(400).json({ error: "Service name is required" });
        }

        const newName = name.trim();
        const db = await openDb();

        // 1. Fetch the old value before making updates
        const oldServiceType = await db.get("SELECT name FROM service_types WHERE id = ?", id);
        if (!oldServiceType) {
            return res.status(404).json({ error: "Service type not found" });
        }

        const oldName = oldServiceType.name;

        // 2. Begin a Transaction to ensure both tables update successfully together
        await db.run("BEGIN TRANSACTION");

        try {
            // Update the master service_types table record
            await db.run("UPDATE service_types SET name = ? WHERE id = ?", newName, id);

            // Update all matching entries in the active services table using the old name reference
            await db.run("UPDATE services SET type = ? WHERE type = ?", newName, oldName);

            await db.run("COMMIT");
        } catch (transactionError) {
            await db.run("ROLLBACK");
            throw transactionError;
        }

        // --- NOTIFICATION LOGIC ---
        // Notify privileged stakeholders about the service modification
        const notifyUsers = await db.all(`
            SELECT id FROM users 
            WHERE role IN ("super_admin", "admin", "sales", "finance", "am_head")
        `);
        const notifyIds = notifyUsers.map(u => u.id).filter(userId => userId != req.user.id);

        if (notifyIds.length > 0) {
            await createNotification(
                notifyIds,
                `Service type '${oldName}' has been renamed to '${newName}' by ${req.user.name}.`,
                'info'
            );
        }

        res.json({
            id: Number(id),
            name: newName,
            message: "Service type and all matching client projects updated successfully."
        });

    } catch (err) {
        if (err.message.includes("UNIQUE")) {
            return res.status(400).json({ error: "A service type with this name already exists" });
        }
        console.error("Service type edit error:", err);
        res.status(500).json({ error: err.message });
    }
});

(async () => {
    try {
        const db = await openDb();
        const usersTable = await db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users'");
        if (usersTable) {
            const tableInfo = await db.all("PRAGMA table_info(users)");
            const hasCreatedAt = tableInfo.some(col => col.name === 'created_at');
            if (!hasCreatedAt) {
                await db.run("ALTER TABLE users ADD COLUMN created_at TEXT");
                await db.run("UPDATE users SET created_at = datetime('now') WHERE created_at IS NULL");
            }
        }

        const clientsTable = await db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='clients'");
        if (clientsTable) {
            await db.run("UPDATE clients SET onboarding_date = date('now') WHERE onboarding_date = '' OR onboarding_date IS NULL");
            const currentMonth = new Date().toISOString().slice(0, 7);
            await db.run("UPDATE invoices SET month = ? WHERE month = '2026-01'", currentMonth);
            await db.run("UPDATE services SET revenue_month = ? WHERE revenue_month = '2026-01'", currentMonth);
        }
    } catch (error) {
        console.error("Error updating database schema/data:", error);
    }
})();

// --- WEBSOCKET SERVER INITIALIZATION ---
const PORT = 5000;
const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

const { WebSocketServer } = require('ws');
const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');

    if (!token) {
        ws.close(1008, 'Token missing');
        return;
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const userId = decoded.id;

        if (!wsClients.has(userId)) {
            wsClients.set(userId, new Set());
        }
        wsClients.get(userId).add(ws);

        ws.on('close', () => {
            const userSockets = wsClients.get(userId);
            if (userSockets) {
                userSockets.delete(ws);
                if (userSockets.size === 0) {
                    wsClients.delete(userId);
                }
            }
        });
    } catch (err) {
        ws.close(1008, 'Invalid token');
    }
});