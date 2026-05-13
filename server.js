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
        const hasFullAccess = ['super_admin', 'admin', 'sales', 'finance', 'am_head'].includes(role) || permissions?.includes('view_all_clients');

        // Auto-correct empty dates so nothing breaks
        await db.run(`UPDATE clients SET onboarding_date = date('now') WHERE onboarding_date = '' OR onboarding_date IS NULL`);

        // The exact SQL parameter to search for anything inside that specific month (e.g., "2026-05%")
        const monthParam = month + '%';

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
            clientFilter = `WHERE (c.account_manager_id = ? OR c.marketing_manager_id = ? OR c.dev_manager_id = ?)`;
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

        // Secondary filter: Except for privileged roles, only show SIGNED and PAID
        const privilegedRoles = ['super_admin', 'admin', 'finance', 'sales', 'am_head', 'marketing_manager', 'dev_manager', 'am_manager'];
        if (!privilegedRoles.includes(role) && !permissions?.includes('view_all_clients')) {
            clientFilter += (clientFilter ? ' AND ' : ' WHERE ') + "c.agreement_status = 'Signed' AND c.invoice_status = 'Paid'";
        }

        // Determine if we connect the next SQL clause with AND or WHERE
        const joiner = clientFilter ? ' AND ' : ' WHERE ';

        // -------------------------------------------------------------
        // CURRENT STATE METRICS (These ignore the month filter)
        // -------------------------------------------------------------
        const mrrRes = await db.get(`SELECT COALESCE(SUM(s.monthly_fee), 0) as total FROM services s JOIN clients c ON s.client_id = c.id ${clientFilter} ${joiner} s.revenue_type = 'Recurring' AND s.status = 'Active'`, params);
        stats.totalMRR = mrrRes?.total || 0;

        const lostRes = await db.get(`SELECT COUNT(DISTINCT c.id) as total FROM clients c ${clientFilter} ${joiner} (EXISTS (SELECT 1 FROM services s2 WHERE s2.client_id = c.id AND (s2.status_color = 'Red' OR s2.status IN ('Hold', 'Pause'))))`, params);
        stats.lostAccounts = lostRes?.total || 0;

        const accCount = await db.get(`SELECT COUNT(DISTINCT c.id) as count FROM clients c ${clientFilter} ${joiner} c.status = 'Active'`, params);
        stats.activeAccounts = accCount?.count || 0;

        const svcCount = await db.get(`SELECT COUNT(*) as count FROM services s JOIN clients c ON s.client_id = c.id ${clientFilter} ${joiner} s.status = 'Active'`, params);
        stats.activeServices = svcCount?.count || 0;

        // -------------------------------------------------------------
        // TIME-BOUND METRICS (These STRICTLY use the month dropdown)
        // -------------------------------------------------------------
        const oneOffRes = await db.get(`SELECT COALESCE(SUM(s.monthly_fee), 0) as total FROM services s JOIN clients c ON s.client_id = c.id ${clientFilter} ${joiner} s.revenue_type = 'One-off' AND s.revenue_month LIKE ?`, [...params, monthParam]);
        stats.oneOffRevenue = oneOffRes?.total || 0;

        const invoiceRes = await db.all(`SELECT i.status, COALESCE(SUM(i.amount), 0) as total, COUNT(*) as count FROM invoices i JOIN clients c ON i.client_id = c.id ${clientFilter} ${joiner} i.month LIKE ? GROUP BY i.status`, [...params, monthParam]);

        // Reset invoice stats to zero before population
        stats.paidInvoices = 0; stats.pendingInvoices = 0; stats.numPaidInvoices = 0; stats.numPendingInvoices = 0;

        invoiceRes.forEach(r => {
            if (r.status === 'Paid') {
                stats.paidInvoices = r.total;
                stats.numPaidInvoices = r.count;
            } else if (r.status === 'Pending') {
                stats.pendingInvoices = r.total;
                stats.numPendingInvoices = r.count;
            }
        });

        // 2. Service Distribution (Current State - Unfiltered by Month)
        const serviceDistribution = await db.all(`
            SELECT s.type, SUM(s.monthly_fee) as revenue, COUNT(DISTINCT s.client_id) as active_accounts
            FROM services s
            JOIN clients c ON s.client_id = c.id
            ${clientFilter}
            ${joiner} s.status = 'Active'
            GROUP BY s.type
        `, params);

        // 3. Account Managers Table (Current State - Unfiltered by Month)
        const amTable = await db.all(`
            SELECT u.name, COUNT(DISTINCT c.id) as num_accounts, COALESCE(SUM(s.monthly_fee), 0) as revenue
            FROM users u
            JOIN clients c ON c.account_manager_id = u.id
            LEFT JOIN services s ON s.client_id = c.id AND s.status = 'Active'
            ${clientFilter ? clientFilter : ''}
            GROUP BY u.id
        `, params);

        // 4. Pending Queues (Action items should always show up regardless of month)
        let pendingReviewClients = [];
        let pendingAssignmentClients = [];
        let pendingOnboardingClients = [];

        // Finance Review Queue
        let pendingQuery = `SELECT id, name, agreement_status, invoice_status, onboarding_date FROM clients c WHERE (agreement_status != 'Signed' OR invoice_status != 'Paid')`;
        let pendingParams = [];
        if (role === 'sales') {
            pendingQuery += ` AND c.onboarding_by = ?`;
            pendingParams.push(id);
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
            WHERE account_manager_id = ? 
            AND (onboarding_pdf_url IS NULL OR onboarding_pdf_url = '')
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
//End Dashboard Data Route (Expanded)

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

// app.post('/api/users', authenticate, isAdmin, async (req, res) => {
//     const db = await openDb();
//     const { name, email, password, role, department, can_add, can_edit, can_delete, permissions } = req.body;
//     if (req.user.role === 'am_head' && role !== 'account_manager') {
//         return res.status(403).json({ message: 'AM Head can only create Account Manager roles' });
//     }

//     const hashedPassword = bcrypt.hashSync(password || 'password123', 10);

//     try {
//         const result = await db.run(
//             'INSERT INTO users (name, email, password, role, department, can_add, can_edit, can_delete, permissions) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
//             name, email, hashedPassword, role, department, can_add || 0, can_edit || 0, can_delete || 0, permissions || '[]'
//         );
//         res.status(201).json({ id: result.lastID, name, email, role, department });
//     } catch (err) {
//         res.status(400).json({ message: 'User already exists' });
//     }
// });

app.post('/api/users', authenticate, isAdmin, async (req, res) => {
    const db = await openDb();
    const { name, email, password, role, department, can_add, can_edit, can_delete, permissions } = req.body;

    if (req.user.role === 'am_head' && role !== 'account_manager') {
        return res.status(403).json({ message: 'AM Head can only create Account Manager roles' });
    }

    const hashedPassword = bcrypt.hashSync(password || 'password123', 10);

    try {
        // Updated to explicitly insert the current date/time into created_at
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
    const isPrivileged = ['super_admin', 'admin', 'sales', 'finance', 'am_head', 'account_manager'].includes(role);

    if (!req.user.can_add && !isPrivileged) {
        return res.status(403).json({ message: 'Forbidden: No permission to add clients' });
    }

    const db = await openDb();
    const { name, email, phone, domain, am_id, mm_id, dm_id, account_manager_id, marketing_manager_id, dev_manager_id, services } = req.body;

    // FIX: Block Duplicate Services on Backend
    if (services && Array.isArray(services)) {
        const types = services.map(s => s.type);
        const uniqueTypes = new Set(types);
        if (types.length !== uniqueTypes.size) {
            return res.status(400).json({ message: 'Duplicate services are not allowed.' });
        }
    }

    const final_am = (am_id || account_manager_id) || null;
    const final_mm = (mm_id || marketing_manager_id) || null;
    const final_dm = (dm_id || dev_manager_id) || null;
    const onboarding_by = req.user.id;

    try {
        const clientRes = await db.run(`
            INSERT INTO clients (name, email, phone, domain, account_manager_id, marketing_manager_id, dev_manager_id, onboarding_date, agreement_status, invoice_status, onboarding_by, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, name, email, phone, domain, final_am, final_mm, final_dm, new Date().toISOString().split('T')[0], 'Pending', 'Pending', onboarding_by, 'Pending');

        const clientId = clientRes.lastID;

        // Add initial services if any
        if (services && Array.isArray(services)) {
            for (const svc of services) {
                await db.run(`
                    INSERT INTO services (client_id, type, monthly_fee, ad_spend, tl_id, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                `, clientId, svc.type, svc.fee || 0, svc.spend || 0, svc.tl_id || null, 'Pending');
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


// Add Service to existing client
app.post('/api/services', authenticate, async (req, res) => {
    const { role } = req.user;
    const isPrivileged = ['super_admin', 'admin', 'sales', 'finance', 'marketing_manager', 'dev_manager'].includes(role);

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

    // FIX: Check if service already exists for THIS client before adding
    const existingService = await db.get('SELECT id FROM services WHERE client_id = ? AND type = ?', client_id, type);
    if (existingService) {
        return res.status(400).json({ message: `This client already has the ${type} service active.` });
    }

    let finalStatus = status || 'Active';
    let status_color = 'Green';
    if (finalStatus === 'Pause') status_color = 'Yellow';
    if (finalStatus === 'Hold') status_color = 'Red';

    try {
        const result = await db.run(`
            INSERT INTO services (client_id, type, monthly_fee, ad_spend, tl_id, status, status_color, revenue_type, revenue_month)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, client_id, type, monthly_fee || 0, ad_spend || 0, tl_id || null, finalStatus, status_color, revenue_type || 'Recurring', revenue_month || null);

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
    } else if (role === 'finance' || role === 'am_head' || role === 'sales') {
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
    try {
        const db = await openDb();
        const client = await db.get('SELECT * FROM clients WHERE id = ?', id);

        if (!client) {
            return res.status(404).json({ message: 'Client not found' });
        }

        // Fetch names separately to avoid complex JOIN issues
        const am = client.account_manager_id ? await db.get('SELECT name FROM users WHERE id = ?', client.account_manager_id) : null;
        const mm = client.marketing_manager_id ? await db.get('SELECT name FROM users WHERE id = ?', client.marketing_manager_id) : null;
        const dm = client.dev_manager_id ? await db.get('SELECT name FROM users WHERE id = ?', client.dev_manager_id) : null;
        const ah = client.am_head_id ? await db.get('SELECT name FROM users WHERE id = ?', client.am_head_id) : null;

        // --- NEW: Fetch the Team Leader Name ---
        //const tl = client.team_leader_id ? await db.get('SELECT name FROM users WHERE id = ?', client.team_leader_id) : null;

        client.am_name = am?.name;
        client.mm_name = mm?.name;
        client.dm_name = dm?.name;
        client.am_head_name = ah?.name;

        // --- NEW: Attach the Team Leader name to the response ---
        //client.team_leader_name = tl?.name;

        const services = await db.all(`
            SELECT s.*, u.name as tl_name 
            FROM services s
            LEFT JOIN users u ON s.tl_id = u.id
            WHERE s.client_id = ?
        `, id);

        res.json({ client, services });
    } catch (err) {
        res.status(500).json({ message: 'Internal server error', error: err.message });
    }
});

// Update Client Basic Info
app.put('/api/clients/:id', authenticate, async (req, res) => {
    const { role } = req.user;
    const isPrivileged = ['super_admin', 'admin', 'sales', 'finance', 'am_head', 'marketing_manager', 'dev_manager'].includes(role);

    if (!req.user.can_edit && !isPrivileged) {
        return res.status(403).json({ message: 'Forbidden: No permission to edit clients' });
    }

    const db = await openDb();
    const { id } = req.params;
    const { name, email, phone, domain, am_id, mm_id, dm_id, account_manager_id, marketing_manager_id, dev_manager_id, am_head_id, status } = req.body;

    // FIX: Force empty strings to become proper NULLs
    const incoming_am = (am_id || account_manager_id) || null;
    const incoming_mm = (mm_id || marketing_manager_id) || null;
    const incoming_dm = (dm_id || dev_manager_id) || null;

    try {
        const existing = await db.get('SELECT * FROM clients WHERE id = ?', id);
        if (!existing) return res.status(404).json({ message: 'Client not found' });

        // Logic check for role-based assignment restrictions
        let final_am = incoming_am;
        let final_mm = incoming_mm;
        let final_dm = incoming_dm;
        let final_am_head = am_head_id || null; // Force null
        //let final_tl = team_leader_id || null; // Force null

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
    const updates = req.body;
    const db = await openDb();

    try {
        const client = await db.get('SELECT * FROM clients WHERE id = ?', id);
        if (!client) return res.status(404).json({ message: 'Client not found' });

        let newStatus = updates.status !== undefined ? updates.status : client.status;

        // --- FIX: 1. Auto-clear managers if status drops to Pending ---
        if (newStatus === 'Pending') {
            updates.marketing_manager_id = null;
            updates.dev_manager_id = null;
            updates.am_head_id = null;
            updates.account_manager_id = null; // Clear AM too just in case
        } else {
            // --- FIX: 2. Allow user to explicitly select "Assign..." to clear the box ---
            if (updates.marketing_manager_id === "") updates.marketing_manager_id = null;
            if (updates.dev_manager_id === "") updates.dev_manager_id = null;
            if (updates.am_head_id === "") updates.am_head_id = null;
        }

        // --- FIX: 3. Dynamically build SET clause to allow actual NULLs to be saved ---
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

        // If both are Signed and Paid, notify managers
        if (updates.agreement_status === 'Signed' || updates.invoice_status === 'Paid') {
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
    const isPrivileged = ['super_admin', 'admin', 'sales', 'finance', 'marketing_manager', 'dev_manager'].includes(role);

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

    // --- FIX: Auto-calculate the status color based on the selected status ---
    let finalStatus = status || 'Active';
    let status_color = 'Green';
    if (finalStatus === 'Pause') status_color = 'Yellow';
    if (finalStatus === 'Hold') status_color = 'Red';

    const db = await openDb();
    try {
        // FIX: Insert the calculated status_color into the database
        const result = await db.run(`
            INSERT INTO services (client_id, type, monthly_fee, ad_spend, tl_id, status, status_color, revenue_type, revenue_month)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, client_id, type, monthly_fee || 0, ad_spend || 0, tl_id || null, finalStatus, status_color, revenue_type || 'Recurring', revenue_month || null);

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
    const isPrivileged = ['super_admin', 'admin', 'sales', 'finance', 'marketing_manager', 'dev_manager'].includes(role);

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

    // --- FIX: Auto-calculate the status color based on the selected status ---
    let status_color = 'Green';
    if (status === 'Pause') status_color = 'Yellow';
    if (status === 'Hold') status_color = 'Red';

    try {
        const existing = await db.get('SELECT * FROM services WHERE id = ?', id);
        if (!existing) return res.status(404).json({ message: 'Service not found' });

        // FIX: Update the status_color in the database
        await db.run(`
            UPDATE services 
            SET type = ?, monthly_fee = ?, ad_spend = ?, tl_id = ?, status = ?, status_color = ?, revenue_type = ?, revenue_month = ?
            WHERE id = ?
        `, type, monthly_fee || 0, ad_spend || 0, tl_id, status, status_color, revenue_type, revenue_month, id);

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

    const isAMHead = role === 'am_head' || role === 'super_admin' || role === 'admin';
    const isMM = (role === 'marketing_manager' && client.marketing_manager_id === userId) || role === 'super_admin' || role === 'admin';
    const isDM = (role === 'dev_manager' && client.dev_manager_id === userId) || role === 'super_admin' || role === 'admin';

    try {
        // --- FIX: Check against undefined, because "" is falsy and was being ignored! ---
        if (account_manager_id !== undefined && isAMHead) {
            const finalAm = account_manager_id === "" ? null : account_manager_id;
            await db.run('UPDATE clients SET account_manager_id = ? WHERE id = ?', finalAm, id);
            if (finalAm) {
                await createNotification(finalAm, `New account assigned: ${client.name}. Please start onboarding.`, 'assignment');
            }
        }

        if (tl_id !== undefined && service_type && (isMM || isDM)) {
            const finalTl = tl_id === "" ? null : tl_id;
            await db.run('UPDATE services SET tl_id = ? WHERE client_id = ? AND type = ?', finalTl, id, service_type);
            if (finalTl) {
                await createNotification(finalTl, `You have been assigned as TL for ${service_type} on client ${client.name}`, 'assignment');
            }
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
    let { status, status_color } = req.body;

    try {
        const existing = await db.get('SELECT s.*, c.name as client_name FROM services s JOIN clients c ON s.client_id = c.id WHERE s.id = ?', id);
        if (!existing) return res.status(404).json({ message: 'Service not found' });

        // --- FIX: Strictly sync colors and statuses ---
        if (status && !status_color) {
            if (status === 'Active') status_color = 'Green';
            if (status === 'Pause') status_color = 'Yellow';
            if (status === 'Hold') status_color = 'Red';
        } else if (status_color && !status) {
            if (status_color === 'Green') status = 'Active';
            if (status_color === 'Yellow') status = 'Pause';
            if (status_color === 'Red') status = 'Hold';
        }

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

        res.json({ success: true, status, status_color });
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

// --- DYNAMIC SERVICE TYPES BLOCK ---

// 1. Initialize the Service Types Table & Insert Default Values
// (async () => {
//     try {
//         const db = await openDb();
//         // Create table if it doesn't exist
//         await db.run(`CREATE TABLE IF NOT EXISTS service_types (
//             id INTEGER PRIMARY KEY AUTOINCREMENT,
//             name TEXT UNIQUE NOT NULL
//         )`);

//         // Check if the table is empty
//         const countRes = await db.get("SELECT COUNT(*) as count FROM service_types");

//         // If empty, insert the default hardcoded services
//         if (countRes.count === 0) {
//             const defaultServices = ['SEO', 'G-ADS', 'META', 'EMAIL', 'SMM', 'Development'];
//             console.log("Seeding default service types...");

//             for (const service of defaultServices) {
//                 await db.run("INSERT OR IGNORE INTO service_types (name) VALUES (?)", service);
//             }
//             console.log("Default services seeded successfully.");
//         }
//     } catch (err) {
//         console.error("Failed to ensure service_types table:", err);
//     }
// })();

// 2. GET endpoint to fetch all dynamic service types
app.get('/api/service-types', authenticate, async (req, res) => {
    try {
        const db = await openDb();
        const rows = await db.all("SELECT * FROM service_types ORDER BY id ASC");
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. POST endpoint to add a new service type
app.post('/api/service-types', authenticate, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name || name.trim() === '') {
            return res.status(400).json({ error: "Service name is required" });
        }

        const db = await openDb();
        const result = await db.run("INSERT INTO service_types (name) VALUES (?)", name.trim());
        res.status(201).json({ id: result.lastID, name: name.trim() });
    } catch (err) {
        if (err.message.includes("UNIQUE")) {
            return res.status(400).json({ error: "Service already exists" });
        }
        res.status(500).json({ error: err.message });
    }
});

// --- END DYNAMIC SERVICE TYPES BLOCK ---

// ==========================================
// Profile Routes
// ==========================================

// 1. GET: Fetch latest profile data AND mint a fresh token (Replaces your two old GET routes)
app.get('/api/profile', authenticate, async (req, res) => {
    const db = await openDb();
    try {
        const user = await db.get('SELECT * FROM users WHERE id = ?', req.user.id);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        delete user.password; // Secure the payload

        // Parse permissions securely
        let permissions = [];
        try {
            permissions = user.permissions ? JSON.parse(user.permissions) : [];
        } catch (e) {
            permissions = [];
        }
        user.permissions = permissions;

        // MINT A FRESH TOKEN WITH THE LATEST DB PERMISSIONS
        const freshToken = jwt.sign({
            id: user.id,
            role: user.role,
            name: user.name,
            can_add: user.can_add,
            can_edit: user.can_edit,
            can_delete: user.can_delete,
            permissions: permissions
        }, process.env.JWT_SECRET || 'supersecretkey', { expiresIn: '8h' });

        res.json({ user, token: freshToken });
    } catch (err) {
        console.error("[API] Profile fetch error:", err.message);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// 2. PUT: Update user profile details (KEEP THIS EXACTLY AS YOU HAD IT)
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

// app.get('/api/profile', authenticate, async (req, res) => {
//     console.log("2")
//     const db = await openDb();
//     const user = await db.get('SELECT id, name, email, phone, role, department, location, avatar_url FROM users WHERE id = ?', req.user.id);
//     res.json({ user });
// });

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
// End Profile Routes

// --- AUTO MIGRATE USERS TABLE ---
// (async () => {
//     try {
//         const db = await openDb();
//         // Check if created_at exists in users table
//         const tableInfo = await db.all("PRAGMA table_info(users)");
//         const hasCreatedAt = tableInfo.some(col => col.name === 'created_at');

//         if (!hasCreatedAt) {
//             console.log("[DB] Adding created_at column to users table...");

//             // Fix: SQLite requires plain columns when altering tables
//             await db.run("ALTER TABLE users ADD COLUMN created_at TEXT");

//             // Manually set the current date for all existing users
//             await db.run("UPDATE users SET created_at = datetime('now') WHERE created_at IS NULL");

//             console.log("[DB] Updated existing users with the current date.");
//         }
//     } catch (error) {
//         console.error("Error updating users table schema:", error);
//     }
// })();

// --- AUTO MIGRATE USERS & CLEAN UP CLIENT DATES ---
(async () => {
    try {
        const db = await openDb();

        // 1. Safely check if the 'users' table exists before altering it
        const usersTable = await db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users'");
        if (usersTable) {
            const tableInfo = await db.all("PRAGMA table_info(users)");
            const hasCreatedAt = tableInfo.some(col => col.name === 'created_at');

            if (!hasCreatedAt) {
                console.log("[DB] Adding created_at column to users table...");
                await db.run("ALTER TABLE users ADD COLUMN created_at TEXT");
                await db.run("UPDATE users SET created_at = datetime('now') WHERE created_at IS NULL");
                console.log("[DB] Updated existing users with the current date.");
            }
        }

        // 2. Safely check if 'clients' table exists before fixing dates
        const clientsTable = await db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='clients'");
        if (clientsTable) {
            const dateFixResult = await db.run("UPDATE clients SET onboarding_date = date('now') WHERE onboarding_date = '' OR onboarding_date IS NULL");
            if (dateFixResult.changes > 0) {
                console.log(`[DB] Successfully fixed ${dateFixResult.changes} clients with empty onboarding dates.`);
            }

            // 3. NEW FIX: Correct the hardcoded '2026-01' dummy data from seed.js to the current month
            const currentMonth = new Date().toISOString().slice(0, 7);
            const invoiceFix = await db.run("UPDATE invoices SET month = ? WHERE month = '2026-01'", currentMonth);
            const serviceFix = await db.run("UPDATE services SET revenue_month = ? WHERE revenue_month = '2026-01'", currentMonth);

            if (invoiceFix.changes > 0 || serviceFix.changes > 0) {
                console.log(`[DB] Successfully moved hardcoded January dummy data to current month.`);
            }
        }

    } catch (error) {
        console.error("Error updating database schema/data:", error);
    }
})();
// --- END AUTO MIGRATE ---

const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
