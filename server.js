const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const openDb = require('./db');
const { logToFile } = require('./logger');

const app = express();
app.use(cors());
app.use(express.json());

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

// Login Route
app.post('/api/login', async (req, res) => {
    const db = await openDb();
    const { email, password } = req.body;
    const user = await db.get('SELECT * FROM users WHERE email = ?', email);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Parse permissions from DB string to array
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

// Helper for Notifications
const createNotification = async (userIds, message, type = 'info') => {
    const db = await openDb();
    const ids = Array.isArray(userIds) ? userIds : [userIds];
    for (const id of ids) {
        await db.run('INSERT INTO notifications (user_id, message, type) VALUES (?, ?, ?)', id, message, type);
    }
};

// Profile Routes
app.get('/api/profile', authenticate, async (req, res) => {
    const db = await openDb();
    const user = await db.get('SELECT id, name, email, phone, role, department, location, avatar_url FROM users WHERE id = ?', req.user.id);
    res.json({ user });
});

app.put('/api/profile', authenticate, async (req, res) => {
    const db = await openDb();
    const { name, location, avatar_url, password } = req.body;

    try {
        if (password) {
            const hashedPassword = bcrypt.hashSync(password, 10);
            await db.run('UPDATE users SET name = ?, location = ?, avatar_url = ?, password = ? WHERE id = ?',
                name, location, avatar_url, hashedPassword, req.user.id);
        } else {
            await db.run('UPDATE users SET name = ?, location = ?, avatar_url = ? WHERE id = ?',
                name, location, avatar_url, req.user.id);
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to update profile' });
    }
});

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

// Dashboard Data Route (Expanded)
app.get('/api/dashboard', authenticate, async (req, res) => {
    try {
        const db = await openDb();
        const { id, role, permissions } = req.user;
        const month = (req.query.month && req.query.month !== 'undefined' && req.query.month !== 'null') ? req.query.month : new Date().toISOString().slice(0, 7);
        const view = req.query.view || 'team'; // 'team' or 'mine'
        const hasFullAccess = ['super_admin', 'admin', 'finance', 'am_head'].includes(role) || permissions?.includes('view_all_clients');

        // Trigger recurring alerts in background
        const triggerNotifications = async () => {
            try {
                const today = new Date();
                const currentDay = today.getDate();
                const currentMonthStr = today.toISOString().slice(0, 7);
                const ldb = await openDb();
                
                const clientsToNotify = await ldb.all(`
                    SELECT * FROM clients 
                    WHERE CAST(recurring_day AS INTEGER) = ?
                `, [currentDay]);

                for (const c of clientsToNotify) {
                    const alreadyNotified = await ldb.get(`
                        SELECT 1 FROM notifications 
                        WHERE message LIKE ? 
                        AND created_at LIKE ? 
                        LIMIT 1
                    `, [`%Recurring payment review needed for ${c.name}%`, `${currentMonthStr}%`]);

                    if (!alreadyNotified) {
                        const managers = await ldb.all('SELECT id FROM users WHERE role IN ("super_admin", "admin", "finance", "am_head")');
                        const managerIds = managers.map(m => m.id);
                        if (c.account_manager_id) managerIds.push(c.account_manager_id);
                        if (c.marketing_manager_id) managerIds.push(c.marketing_manager_id);
                        if (c.dev_manager_id) managerIds.push(c.dev_manager_id);

                        await createNotification(
                            [...new Set(managerIds)],
                            `Recurring payment review needed for ${c.name} (Day ${c.recurring_day})`,
                            'payment'
                        );
                    }
                }
            } catch (notifyErr) {
                console.error("Notification trigger failed:", notifyErr);
            }
        };
        triggerNotifications(); // Fire and forget

        // 1. Fetch Stats
        const stats = {
            totalMRR: 0,
            oneOffRevenue: 0,
            activeAccounts: 0,
            activeServices: 0,
            pendingInvoices: 0,
            paidInvoices: 0,
            lostAccounts: 0
        };

        // Base filters for RBAC
        let clientFilter = '';
        let params = [];

        // If AM Head/Admin/Manager wants to see only their OWN accounts
        if (view === 'mine' && (role === 'am_head' || role === 'marketing_manager' || role === 'dev_manager' || role === 'super_admin' || role === 'admin')) {
            clientFilter = `WHERE c.account_manager_id = ? OR c.marketing_manager_id = ? OR c.dev_manager_id = ?`;
            params = [id, id, id];
        } else if (hasFullAccess) {
            clientFilter = '';
        } else if (role === 'sales') {
            clientFilter = `WHERE c.onboarding_by = ?`;
            params = [id];
        } else if (role === 'marketing_manager' || permissions?.includes('marketing_manager')) {
            clientFilter = `WHERE c.marketing_manager_id = ?`;
            params = [id];
        } else if (role === 'dev_manager' || permissions?.includes('dev_manager')) {
            clientFilter = `WHERE c.dev_manager_id = ?`;
            params = [id];
        } else if (role === 'account_manager' || permissions?.includes('account_manager')) {
            clientFilter = `WHERE c.account_manager_id = ?`;
            params = [id];
        } else {
            // Staff/TLs
            clientFilter = `WHERE EXISTS (SELECT 1 FROM services s2 WHERE s2.client_id = c.id AND s2.tl_id = ?)`;
            params = [id];
        }

        console.log(`[Dashboard] Role: ${role}, ID: ${id}, Filter: ${clientFilter}, Params:`, params);

        // Secondary filter: Except for privileged roles, only show SIGNED and PAID
        const privilegedRoles = ['super_admin', 'admin', 'finance', 'sales', 'am_head', 'marketing_manager', 'dev_manager', 'am_manager'];
        if (!privilegedRoles.includes(role) && !permissions?.includes('view_all_clients')) {
            clientFilter += (clientFilter ? ' AND ' : ' WHERE ') + "c.agreement_status = 'Signed' AND c.invoice_status = 'Paid'";
        }

        // Metrics Queries
        const mrrRes = await db.get(`SELECT COALESCE(SUM(s.monthly_fee), 0) as total FROM services s JOIN clients c ON s.client_id = c.id ${clientFilter} ${clientFilter ? 'AND' : 'WHERE'} s.revenue_type = 'Recurring' AND s.status = 'Active'`, params);
        stats.totalMRR = mrrRes?.total || 0;

        const lostRes = await db.get(`SELECT COUNT(DISTINCT c.id) as total FROM clients c ${clientFilter} ${clientFilter ? 'AND' : 'WHERE'} (EXISTS (SELECT 1 FROM services s2 WHERE s2.client_id = c.id AND (s2.status_color = 'Red' OR s2.status IN ('Hold', 'Pause'))))`, params);
        stats.lostAccounts = lostRes?.total || 0;

        const oneOffRes = await db.get(`SELECT COALESCE(SUM(s.monthly_fee), 0) as total FROM services s JOIN clients c ON s.client_id = c.id ${clientFilter} ${clientFilter ? 'AND' : 'WHERE'} s.revenue_type = 'One-off' AND s.revenue_month = ?`, [...params, month]);
        stats.oneOffRevenue = oneOffRes?.total || 0;

        const accCount = await db.get(`SELECT COUNT(DISTINCT s.client_id) as count FROM services s JOIN clients c ON s.client_id = c.id ${clientFilter} ${clientFilter ? 'AND' : 'WHERE'} s.status = 'Active'`, params);
        stats.activeAccounts = accCount?.count || 0;

        const svcCount = await db.get(`SELECT COUNT(*) as count FROM services s JOIN clients c ON s.client_id = c.id ${clientFilter} ${clientFilter ? 'AND' : 'WHERE'} s.status = 'Active'`, params);
        stats.activeServices = svcCount?.count || 0;

        const invoiceRes = await db.all(`SELECT i.status, COALESCE(SUM(i.amount), 0) as total, COUNT(*) as count FROM invoices i JOIN clients c ON i.client_id = c.id ${clientFilter} ${clientFilter ? 'AND' : 'WHERE'} i.month = ? GROUP BY i.status`, [...params, month]);

        // Reset invoice stats to zero before population
        stats.paidInvoices = 0;
        stats.pendingInvoices = 0;
        stats.numPaidInvoices = 0;
        stats.numPendingInvoices = 0;

        invoiceRes.forEach(r => {
            if (r.status === 'Paid') {
                stats.paidInvoices = r.total;
                stats.numPaidInvoices = r.count;
            } else if (r.status === 'Pending') {
                stats.pendingInvoices = r.total;
                stats.numPendingInvoices = r.count;
            }
        });

        // 2. Service Distribution (Type, Revenue, Active Accounts)
        const serviceDistribution = await db.all(`
        SELECT 
            s.type, 
            SUM(s.monthly_fee) as revenue, 
            COUNT(DISTINCT s.client_id) as active_accounts
        FROM services s
        JOIN clients c ON s.client_id = c.id
        ${clientFilter}
        ${clientFilter ? 'AND' : 'WHERE'} s.status = 'Active'
        GROUP BY s.type
    `, params);

        // 3. Account Managers Table (Name, Accounts, Revenue)
        const amTable = await db.all(`
        SELECT 
            u.name, 
            COUNT(DISTINCT c.id) as num_accounts, 
            COALESCE(SUM(s.monthly_fee), 0) as revenue
        FROM users u
        JOIN clients c ON c.account_manager_id = u.id
        LEFT JOIN services s ON s.client_id = c.id AND s.status = 'Active'
        ${clientFilter ? clientFilter : ''}
        GROUP BY u.id
    `, params);

        // 4. Pending Queues
        let pendingReviewClients = [];
        let pendingAssignmentClients = [];
        let pendingOnboardingClients = [];

        // Finance Review Queue
        let pendingQuery = `SELECT id, name, agreement_status, invoice_status, onboarding_date FROM clients c WHERE (agreement_status != 'Signed' OR invoice_status != 'Paid')`;
        let pendingParams = [];
        if (role === 'sales') {
            pendingQuery += ` AND c.onboarding_by = ?`;
            pendingParams = [id];
        }
        pendingQuery += ` ORDER BY onboarding_date DESC LIMIT 10`;
        pendingReviewClients = await db.all(pendingQuery, pendingParams);

        // Assignment Queue (For Heads)
        if (hasFullAccess || role === 'marketing_manager' || role === 'dev_manager') {
            pendingAssignmentClients = await db.all(`
                SELECT id, name, marketing_manager_id, dev_manager_id, am_head_id, account_manager_id 
                FROM clients 
                WHERE agreement_status = 'Signed' AND invoice_status = 'Paid'
                AND (account_manager_id IS NULL OR EXISTS (SELECT 1 FROM services s WHERE s.client_id = clients.id AND s.tl_id IS NULL))
                LIMIT 10
            `);
        }

        // Onboarding Queue (For AMs)
        pendingOnboardingClients = await db.all(`
            SELECT id, name, onboarding_date, onboarding_pdf_url 
            FROM clients 
            WHERE account_manager_id = ? AND onboarding_date IS NULL
            LIMIT 10
        `, [id]);

        res.json({
            stats,
            serviceDistribution,
            accountManagers: amTable,
            pendingReviewClients,
            pendingAssignmentClients,
            pendingOnboardingClients
        });
    } catch (err) {
        console.error("Dashboard error:", err);
        res.status(500).json({ message: 'Failed to fetch dashboard data', error: err.message });
    }
});

// Middleware to check if user is admin or has management permission
const isAdmin = (req, res, next) => {
    const { role, permissions } = req.user;
    const isPrivileged = role === 'super_admin' || role === 'admin' || role === 'am_head' || permissions?.includes('manage_staff');

    if (!isPrivileged) {
        return res.status(403).json({ message: 'Forbidden: Management access required' });
    }
    next();
};

// User Management Routes
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
            'INSERT INTO users (name, email, password, role, department, can_add, can_edit, can_delete, permissions) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
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
    res.json({ success: true });
});

app.delete('/api/users/:id', authenticate, isAdmin, async (req, res) => {
    const db = await openDb();
    const { id } = req.params;

    // Prevent deleting self
    if (parseInt(id) === req.user.id) {
        return res.status(400).json({ message: 'Cannot delete yourself' });
    }

    await db.run('DELETE FROM users WHERE id = ?', id);
    res.json({ success: true });
});

// Client Management - Add Client
app.post('/api/clients', authenticate, async (req, res) => {
    const { role } = req.user;
    const isPrivileged = ['super_admin', 'admin', 'am_head', 'marketing_manager', 'dev_manager'].includes(role);

    if (!req.user.can_add && !isPrivileged) {
        return res.status(403).json({ message: 'Forbidden: No permission to add clients' });
    }

    const db = await openDb();
    const { name, email, phone, domain, am_id, mm_id, dm_id, account_manager_id, marketing_manager_id, dev_manager_id, services } = req.body;

    // Resolve IDs (support both shorthand from Add modal and longhand from Edit modal/state)
    const final_am = am_id || account_manager_id;
    const final_mm = mm_id || marketing_manager_id;
    const final_dm = dm_id || dev_manager_id;

    const onboarding_by = req.user.id;

    try {
        const clientRes = await db.run(`
            INSERT INTO clients (name, email, phone, domain, account_manager_id, marketing_manager_id, dev_manager_id, onboarding_date, agreement_status, invoice_status, onboarding_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, name, email, phone, domain, final_am, final_mm, final_dm, new Date().toISOString().split('T')[0], 'Pending', 'Pending', onboarding_by);

        const clientId = clientRes.lastID;

        // Add initial services if any
        if (services && Array.isArray(services)) {
            for (const svc of services) {
                await db.run(`
                    INSERT INTO services (client_id, type, monthly_fee, ad_spend, tl_id, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                `, clientId, svc.type, svc.fee || 0, svc.spend || 0, svc.tl_id || null, 'Active');
            }
        }

        res.status(201).json({ id: clientId, name });

        // Notification: Notify Finance about new onboarding
        const financeUsers = await db.all('SELECT id FROM users WHERE role = "finance" OR role = "super_admin" OR role = "admin"');
        await createNotification(financeUsers.map(u => u.id), `New client onboarded: ${name}. Pending finance review.`, 'onboarding');

    } catch (err) {
        res.status(500).json({ message: 'Failed to create client', error: err.message });
    }
});

// Project Analysis (Detailed per Service)
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

    // Filter logic
    if (view === 'mine' && isPrivileged) {
        filters.push('(c.account_manager_id = ? OR c.marketing_manager_id = ? OR c.dev_manager_id = ? OR s.tl_id = ?)');
        params.push(id, id, id, id);
    } else if (role === 'finance' || role === 'am_head') {
        // AM Head and Finance see all by default (Team View)
    } else if (role !== 'super_admin' && role !== 'admin') {
        // Regular staff only see APPROVED clients
        filters.push("c.agreement_status = 'Signed' AND c.invoice_status = 'Paid'");

        if (department === 'SEO') {
            filters.push('s.type = "SEO"');
        } else if (department === 'Paid Ads') {
            filters.push('s.type IN ("G-ADS", "META")');
        } else if (department === 'Development') {
            filters.push('s.type = "Development"');
        } else if (department === 'Marketing') {
            filters.push('s.type IN ("SEO", "G-ADS", "META", "EMAIL", "SMM")');
        } else {
            // General staff see only their assigned
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

// Get Clients with AM and basic revenue info
app.get('/api/clients', authenticate, async (req, res) => {
    const db = await openDb();
    const { role, id, permissions } = req.user;
    const canViewRevenue = ['super_admin', 'admin', 'finance', 'am_head'].includes(role) || permissions?.includes('view_revenue');
    const hasFullAccess = ['super_admin', 'admin', 'finance', 'am_head'].includes(role) || permissions?.includes('view_all_clients');

    let query = `
        SELECT c.*, u.name as am_name,
               ${canViewRevenue ? "(SELECT SUM(monthly_fee) FROM services WHERE client_id = c.id AND revenue_type = 'Recurring' AND status = 'Active')" : "0"} as recurring_revenue,
               ${canViewRevenue ? "(SELECT SUM(monthly_fee) FROM services WHERE client_id = c.id AND revenue_type = 'One-off')" : "0"} as one_off_revenue
        FROM clients c
        LEFT JOIN users u ON c.account_manager_id = u.id
    `;
    let params = [];

    const view = req.query.view || 'team';

    if (view === 'mine' && hasFullAccess) {
        query += ` WHERE (c.account_manager_id = ? OR c.marketing_manager_id = ? OR c.dev_manager_id = ? OR c.am_head_id = ? OR c.onboarding_by = ?
                   OR EXISTS (SELECT 1 FROM services s2 WHERE s2.client_id = c.id AND s2.tl_id = ?))`;
        params = [id, id, id, id, id, id];
    } else if (hasFullAccess) {
        // Full visibility
    } else if (role === 'sales') {
        query += ` WHERE c.onboarding_by = ?`;
        params = [id];
    } else {
        query += ` WHERE (c.account_manager_id = ? OR c.marketing_manager_id = ? OR c.dev_manager_id = ? OR c.am_head_id = ? OR c.onboarding_by = ?
                   OR EXISTS (SELECT 1 FROM services s2 WHERE s2.client_id = c.id AND s2.tl_id = ?))
                   AND (c.agreement_status = 'Signed' AND c.invoice_status = 'Paid')`;
        params = [id, id, id, id, id, id];
    }

    const clients = await db.all(query, params);

    // Efficiently fetch services for all retrieved clients in one query
    if (clients.length > 0) {
        const clientIds = clients.map(c => c.id).filter(id => id != null);
        if (clientIds.length > 0) {
            const placeholders = clientIds.map(() => '?').join(',');
            const allServices = await db.all(`
                SELECT client_id, type 
                FROM services 
                WHERE client_id IN (${placeholders}) AND status = 'Active'
            `, clientIds);

            // Map services back to their respective clients
            clients.forEach(client => {
                client.services = allServices.filter(s => s.client_id === client.id);
            });
        } else {
            clients.forEach(c => c.services = []);
        }
    }

    res.json({ clients });
});

// Get Single Client with Services
app.get('/api/clients/:id', authenticate, async (req, res) => {
    const { id } = req.params;
    logToFile(`[API] Fetching details for client ID: ${id}`);

    try {
        const db = await openDb();

        // Simplified query for testing
        const client = await db.get('SELECT * FROM clients WHERE id = ?', id);

        if (!client) {
            logToFile(`[API] Client NOT FOUND: ${id}`);
            return res.status(404).json({ message: 'Client not found' });
        }

        // Fetch names separately to avoid complex JOIN issues
        const am = client.account_manager_id ? await db.get('SELECT name FROM users WHERE id = ?', client.account_manager_id) : null;
        const mm = client.marketing_manager_id ? await db.get('SELECT name FROM users WHERE id = ?', client.marketing_manager_id) : null;
        const dm = client.dev_manager_id ? await db.get('SELECT name FROM users WHERE id = ?', client.dev_manager_id) : null;
        const ah = client.am_head_id ? await db.get('SELECT name FROM users WHERE id = ?', client.am_head_id) : null;

        client.am_name = am?.name;
        client.mm_name = mm?.name;
        client.dm_name = dm?.name;
        client.am_head_name = ah?.name;

        logToFile(`[API] Found client: ${client.name}`);

        const services = await db.all(`
            SELECT s.*, u.name as tl_name 
            FROM services s
            LEFT JOIN users u ON s.tl_id = u.id
            WHERE s.client_id = ?
        `, id);

        logToFile(`[API] Found ${services.length} services`);
        res.json({ client, services });
    } catch (err) {
        logToFile(`[API] ERROR fetching client ${id}: ${err.message}`);
        res.status(500).json({ message: 'Internal server error', error: err.message });
    }
});

// Update Client Basic Info
app.put('/api/clients/:id', authenticate, async (req, res) => {
    const { role } = req.user;
    const isPrivileged = ['super_admin', 'admin', 'am_head', 'marketing_manager', 'dev_manager'].includes(role);

    if (!req.user.can_edit && !isPrivileged) {
        return res.status(403).json({ message: 'Forbidden: No permission to edit clients' });
    }

    const db = await openDb();
    const { id } = req.params;
    const { name, email, phone, domain, am_id, mm_id, dm_id, account_manager_id, marketing_manager_id, dev_manager_id, am_head_id, status } = req.body;

    // Resolve IDs
    const incoming_am = am_id || account_manager_id;
    const incoming_mm = mm_id || marketing_manager_id;
    const incoming_dm = dm_id || dev_manager_id;

    try {
        const existing = await db.get('SELECT * FROM clients WHERE id = ?', id);
        if (!existing) return res.status(404).json({ message: 'Client not found' });

        // Logic check for role-based assignment restrictions
        let final_am = incoming_am;
        let final_mm = incoming_mm;
        let final_dm = incoming_dm;
        let final_am_head = am_head_id; // Add this from req.body

        if (role === 'am_head') {
            // AM Head can only change Account Manager
            final_mm = existing.marketing_manager_id;
            final_dm = existing.dev_manager_id;
        } else if (role === 'marketing_manager') {
            // Marketing Manager can only change MM (and TLs in services)
            final_am = existing.account_manager_id;
            final_dm = existing.dev_manager_id;
        } else if (role === 'dev_manager') {
            // Dev Manager can only change DM (and TLs in services)
            final_am = existing.account_manager_id;
            final_mm = existing.marketing_manager_id;
        } else if (role === 'sales') {
            // Sales cannot edit managers!
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

        // Notifications for assignments
        if (final_am && final_am !== existing.account_manager_id) {
            await createNotification(final_am, `You have been assigned as the Account Manager for ${name || existing.name}`, 'info');
        }
        if (final_mm && final_mm !== existing.marketing_manager_id) {
            await createNotification(final_mm, `You have been assigned as the Marketing Manager for ${name || existing.name}`, 'info');
        }
        if (final_dm && final_dm !== existing.dev_manager_id) {
            await createNotification(final_dm, `You have been assigned as the Dev Manager for ${name || existing.name}`, 'info');
        }

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to update client', error: err.message });
    }
});

// Update Client Finance Status (Finance/Admin only)
app.patch('/api/clients/:id/finance', authenticate, async (req, res) => {
    const { role } = req.user;
    if (role !== 'super_admin' && role !== 'admin' && role !== 'finance') {
        return res.status(403).json({ message: 'Forbidden' });
    }

    const { id } = req.params;
    const { agreement_status, invoice_status, marketing_manager_id, dev_manager_id, am_head_id, recurring_day } = req.body;
    const db = await openDb();

    try {
        await db.run(`
            UPDATE clients 
            SET agreement_status = COALESCE(?, agreement_status), 
                invoice_status = COALESCE(?, invoice_status),
                marketing_manager_id = COALESCE(?, marketing_manager_id),
                dev_manager_id = COALESCE(?, dev_manager_id),
                am_head_id = COALESCE(?, am_head_id),
                recurring_day = COALESCE(?, recurring_day)
            WHERE id = ?
        `, 
        agreement_status !== undefined ? agreement_status : null, 
        invoice_status !== undefined ? invoice_status : null, 
        marketing_manager_id !== undefined ? marketing_manager_id : null, 
        dev_manager_id !== undefined ? dev_manager_id : null, 
        am_head_id !== undefined ? am_head_id : null, 
        recurring_day !== undefined ? parseInt(recurring_day) : null, 
        id);

        // If both are Signed and Paid, notify managers
        const client = await db.get('SELECT name, marketing_manager_id, dev_manager_id, am_head_id FROM clients WHERE id = ?', id);
        if (agreement_status === 'Signed' || invoice_status === 'Paid') {
            const managers = await db.all('SELECT id FROM users WHERE role IN ("super_admin", "admin", "am_head")');
            const managerIds = managers.map(m => m.id);
            if (client.marketing_manager_id) managerIds.push(client.marketing_manager_id);
            if (client.dev_manager_id) managerIds.push(client.dev_manager_id);
            if (client.am_head_id) managerIds.push(client.am_head_id);

            await createNotification([...new Set(managerIds)], `Client ${client.name} has been updated/verified by Finance.`, 'approval');
        }

        res.json({ success: true });
    } catch (err) {
        logToFile(`[API] FINANCE UPDATE ERROR: ${err.message}`);
        res.status(500).json({ message: 'Failed to update finance status', error: err.message });
    }
});

// Add Service to existing client
app.post('/api/services', authenticate, async (req, res) => {
    const { role } = req.user;
    const isPrivileged = ['super_admin', 'admin', 'marketing_manager', 'dev_manager'].includes(role);

    if (!req.user.can_edit && !isPrivileged) {
        return res.status(403).json({ message: 'Forbidden: No permission to add services' });
    }

    const { client_id, type, monthly_fee, ad_spend, tl_id, status, revenue_type, revenue_month } = req.body;

    if (role === 'marketing_manager' && type === 'Development') {
        return res.status(403).json({ message: 'MM cannot add Development services' });
    }
    if (role === 'dev_manager' && type !== 'Development') {
        return res.status(403).json({ message: 'DM can only add Development services' });
    }

    const db = await openDb();
    try {
        const result = await db.run(`
            INSERT INTO services (client_id, type, monthly_fee, ad_spend, tl_id, status, revenue_type, revenue_month)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, client_id, type, monthly_fee || 0, ad_spend || 0, tl_id || null, status || 'Active', revenue_type || 'Recurring', revenue_month || null);

        const serviceId = result.lastID;

        // Notification for TL assignment
        if (tl_id) {
            const client = await db.get('SELECT name FROM clients WHERE id = ?', client_id);
            await createNotification(tl_id, `You have been assigned as the Team Lead for ${type} service for ${client?.name || 'a client'}`, 'info');
        }

        res.status(201).json({ id: serviceId });
    } catch (err) {
        res.status(500).json({ message: 'Failed to add service', error: err.message });
    }
});

// Update Service
app.put('/api/services/:id', authenticate, async (req, res) => {
    const { role } = req.user;
    const isPrivileged = ['super_admin', 'admin', 'marketing_manager', 'dev_manager'].includes(role);

    if (!req.user.can_edit && !isPrivileged) {
        return res.status(403).json({ message: 'Forbidden: No permission to edit services' });
    }

    const db = await openDb();
    const { id } = req.params;
    const { type, monthly_fee, ad_spend, tl_id, status, revenue_type, revenue_month } = req.body;

    // Type restriction
    if (role === 'marketing_manager' && type === 'Development') {
        return res.status(403).json({ message: 'MM cannot manage Development services' });
    }
    if (role === 'dev_manager' && type !== 'Development') {
        return res.status(403).json({ message: 'DM can only manage Development services' });
    }

    try {
        const existing = await db.get('SELECT * FROM services WHERE id = ?', id);
        if (!existing) return res.status(404).json({ message: 'Service not found' });

        await db.run(`
            UPDATE services 
            SET type = ?, monthly_fee = ?, ad_spend = ?, tl_id = ?, status = ?, revenue_type = ?, revenue_month = ?
            WHERE id = ?
        `, type, monthly_fee || 0, ad_spend || 0, tl_id, status, revenue_type, revenue_month, id);

        // Notification for TL assignment change
        if (tl_id && tl_id !== existing.tl_id) {
            const client = await db.get('SELECT name FROM clients WHERE id = ?', existing.client_id);
            await createNotification(tl_id, `You have been assigned as the Team Lead for ${type || existing.type} service for ${client?.name || 'a client'}`, 'info');
        }

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to update service', error: err.message });
    }
});

// Department Head Assignment (Assign AMs/TLs)
app.patch('/api/clients/:id/assign', authenticate, async (req, res) => {
    const { role, id: userId } = req.user;
    const { id } = req.params;
    const { account_manager_id, tl_id, service_type } = req.body;
    const db = await openDb();

    const client = await db.get('SELECT * FROM clients WHERE id = ?', id);
    if (!client) return res.status(404).json({ message: 'Client not found' });

    // Check if the user is the head of the respective department
    const isAMHead = role === 'am_head' || role === 'super_admin' || role === 'admin';
    const isMM = (role === 'marketing_manager' && client.marketing_manager_id === userId) || role === 'super_admin' || role === 'admin';
    const isDM = (role === 'dev_manager' && client.dev_manager_id === userId) || role === 'super_admin' || role === 'admin';

    try {
        if (account_manager_id && isAMHead) {
            await db.run('UPDATE clients SET account_manager_id = ? WHERE id = ?', account_manager_id, id);
            await createNotification(account_manager_id, `New account assigned: ${client.name}. Please start onboarding.`, 'assignment');
        }

        if (tl_id && service_type && (isMM || isDM)) {
            await db.run('UPDATE services SET tl_id = ? WHERE client_id = ? AND type = ?', tl_id, id, service_type);
            await createNotification(tl_id, `You have been assigned as TL for ${service_type} on client ${client.name}`, 'assignment');
        }

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to assign staff', error: err.message });
    }
});

// AM Onboarding documentation
app.patch('/api/clients/:id/onboarding', authenticate, async (req, res) => {
    const { id } = req.params;
    const { onboarding_date, onboarding_pdf_url } = req.body;
    const db = await openDb();

    try {
        await db.run('UPDATE clients SET onboarding_date = ?, onboarding_pdf_url = ? WHERE id = ?', 
            onboarding_date, onboarding_pdf_url, id);
        
        const client = await db.get('SELECT name FROM clients WHERE id = ?', id);
        const managers = await db.all('SELECT id FROM users WHERE role IN ("super_admin", "admin", "am_head", "finance")');
        await createNotification(managers.map(m => m.id), `Onboarding completed for ${client.name} on ${onboarding_date}`, 'onboarding');

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to update onboarding info' });
    }
});

// Quick Service Status Update (for Projects page)
app.patch('/api/services/:id/status', authenticate, async (req, res) => {
    const db = await openDb();
    const { id } = req.params;
    const { status, status_color } = req.body;

    try {
        const existing = await db.get('SELECT s.*, c.name as client_name FROM services s JOIN clients c ON s.client_id = c.id WHERE s.id = ?', id);

        if (status) await db.run('UPDATE services SET status = ? WHERE id = ?', status, id);
        if (status_color) await db.run('UPDATE services SET status_color = ? WHERE id = ?', status_color, id);

        // Notify managers if status becomes critical
        if ((status && ['Pause', 'Hold'].includes(status)) || (status_color && status_color === 'Red')) {
            const managers = await db.all('SELECT id FROM users WHERE role IN ("super_admin", "admin", "am_head")');
            const managerIds = managers.map(m => m.id);
            if (existing.tl_id) managerIds.push(existing.tl_id);

            await createNotification(
                [...new Set(managerIds)],
                `Critical status update for ${existing.client_name}: ${existing.type} is now ${status || existing.status} (${status_color || existing.status_color})`,
                'warning'
            );
        }

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to update status' });
    }
});

// Invoice Management
app.get('/api/invoices', authenticate, async (req, res) => {
    const db = await openDb();
    const invoices = await db.all(`
        SELECT i.*, c.name as client_name 
        FROM invoices i
        JOIN clients c ON i.client_id = c.id
        ORDER BY i.month DESC
    `);
    res.json({ invoices });
});

app.post('/api/invoices', authenticate, isAdmin, async (req, res) => {
    const db = await openDb();
    const { client_id, amount, status, month } = req.body;
    await db.run('INSERT INTO invoices (client_id, amount, status, month) VALUES (?, ?, ?, ?)', client_id, amount, status, month);
    res.status(201).json({ success: true });
});

// Delete Service
app.delete('/api/services/:id', authenticate, async (req, res) => {
    if (!req.user.can_edit && req.user.role !== 'super_admin' && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Forbidden: No permission to delete services' });
    }

    const db = await openDb();
    const { id } = req.params;

    try {
        await db.run('DELETE FROM services WHERE id = ?', id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to delete service', error: err.message });
    }
});

// Delete Client
app.delete('/api/clients/:id', authenticate, async (req, res) => {
    if (!req.user.can_delete && req.user.role !== 'super_admin' && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Forbidden: No permission to delete clients' });
    }

    const db = await openDb();
    const { id } = req.params;

    try {
        // First delete associated services
        await db.run('DELETE FROM services WHERE client_id = ?', id);
        // Then delete client
        await db.run('DELETE FROM clients WHERE id = ?', id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: 'Failed to delete client', error: err.message });
    }
});

const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
