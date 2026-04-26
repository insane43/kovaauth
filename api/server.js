/**
 * ──────────────────────────────────────────────────────
 *  Kova Auth — License Key Management REST API
 * ──────────────────────────────────────────────────────
 *
 *  This API talks directly to Firebase Realtime Database
 *  via its REST API — no service account needed.
 *
 *  Endpoints:
 *    GET    /api/health           – Health check
 *    POST   /api/keys/create      – Create a new license key
 *    DELETE /api/keys/delete      – Delete a license key
 *    GET    /api/keys/list        – List all keys for an app
 *    GET    /api/keys/verify      – Verify / activate a key
 *    POST   /api/keys/ban         – Ban a license key
 *    POST   /api/keys/unban       – Unban a license key
 *    POST   /api/keys/reset-hwid  – Reset HWID for a key
 *
 *  Auth: every request (except /health) must include headers:
 *    x-owner-id   – your Owner ID from the dashboard
 *    x-app-name   – your Application name
 *    x-app-secret – your Application secret
 */

const express = require('express');
const cors = require('cors');

const server = express();
server.use(cors());
server.use(express.json());

// ── Firebase REST base URL ──────────────────────────
const DB_URL = 'https://kova-42298-default-rtdb.firebaseio.com';

// ── Firebase REST helpers ───────────────────────────

async function fbGet(path) {
    const res = await fetch(`${DB_URL}/${path}.json`);
    if (!res.ok) throw new Error(`Firebase GET ${path} failed: ${res.status}`);
    return res.json();
}

async function fbPut(path, data) {
    const res = await fetch(`${DB_URL}/${path}.json`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`Firebase PUT ${path} failed: ${res.status}`);
    return res.json();
}

async function fbPost(path, data) {
    const res = await fetch(`${DB_URL}/${path}.json`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`Firebase POST ${path} failed: ${res.status}`);
    return res.json();   // returns { name: "-Nxxxx" }
}

async function fbPatch(path, data) {
    const res = await fetch(`${DB_URL}/${path}.json`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`Firebase PATCH ${path} failed: ${res.status}`);
    return res.json();
}

async function fbDelete(path) {
    const res = await fetch(`${DB_URL}/${path}.json`, { method: 'DELETE' });
    if (!res.ok) throw new Error(`Firebase DELETE ${path} failed: ${res.status}`);
    return true;
}

// ── Helpers ─────────────────────────────────────────

function generateLicenseKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const segs = [];
    for (let i = 0; i < 5; i++) {
        let s = '';
        for (let j = 0; j < 4; j++) s += chars[Math.random() * chars.length | 0];
        segs.push(s);
    }
    return segs.join('-');
}

function parseExpiry(value) {
    if (!value) return null;
    const str = String(value).toLowerCase().trim();
    if (str === 'f' || str === 'forever') return 3650 * 86400000;
    if (/^\d+$/.test(str)) return parseInt(str, 10) * 86400000;
    const m = str.match(/^(\d+)([sdmy])$/);
    if (!m) return null;
    const v = parseInt(m[1], 10);
    switch (m[2]) {
        case 's': return v * 1000;
        case 'd': return v * 86400000;
        case 'm': return v * 30 * 86400000;
        case 'y': return v * 365 * 86400000;
        default: return null;
    }
}

// ── Middleware: authenticate API requests ────────────

async function authenticate(req, res, next) {
    const ownerId   = req.headers['x-owner-id']   || req.query.owner_id;
    const appName   = req.headers['x-app-name']    || req.query.app_name;
    const appSecret = req.headers['x-app-secret']  || req.query.app_secret;

    if (!ownerId || !appName || !appSecret) {
        return res.status(401).json({
            success: false,
            message: 'Missing auth. Provide x-owner-id, x-app-name, x-app-secret headers.'
        });
    }

    try {
        // Find the user UID by scanning users for matching ownerId
        const users = await fbGet('users');
        if (!users) {
            return res.status(401).json({ success: false, message: 'Invalid owner ID.' });
        }

        let uid = null;
        for (const [id, profile] of Object.entries(users)) {
            if (profile.ownerId === ownerId) {
                uid = id;
                break;
            }
        }

        if (!uid) {
            return res.status(401).json({ success: false, message: 'Invalid owner ID.' });
        }

        // Find the application
        const apps = await fbGet('applications/' + uid);
        if (!apps) {
            return res.status(404).json({ success: false, message: 'No applications found.' });
        }

        let matchedApp = null;
        let matchedAppId = null;
        for (const [id, app] of Object.entries(apps)) {
            if (app.name === appName && app.secret === appSecret) {
                matchedApp = app;
                matchedAppId = id;
                break;
            }
        }

        if (!matchedApp) {
            return res.status(401).json({ success: false, message: 'Invalid app name or secret.' });
        }

        if (matchedApp.disabled) {
            return res.status(403).json({ success: false, message: 'Application is disabled.' });
        }

        req.kova = { uid, ownerId, app: matchedApp, appId: matchedAppId, appName: matchedApp.name };
        next();
    } catch (err) {
        console.error('Auth error:', err);
        return res.status(500).json({ success: false, message: 'Authentication error.' });
    }
}

// ── Helper: find a license by key string ─────────────

async function findLicense(appId, key) {
    const licenses = await fbGet('licenses/' + appId);
    if (!licenses) return { targetId: null, license: null };

    for (const [id, lic] of Object.entries(licenses)) {
        if (lic.key === key) {
            return { targetId: id, license: lic };
        }
    }
    return { targetId: null, license: null };
}

// ── Helper: log activity ─────────────────────────────

async function logActivity(uid, type, text, detail) {
    const dotMap = {
        creation: 'dot-blue', activation: 'dot-green', expiry: 'dot-red',
        deletion: 'dot-orange', ban: 'dot-red', unban: 'dot-green',
        app: 'dot-purple', reset: 'dot-orange'
    };

    await fbPost('activityLogs/' + uid, {
        type,
        text,
        detail: detail || '',
        time: Date.now(),
        dot: dotMap[type] || 'dot-blue'
    });
}

// ═══════════════════════════════════════════════════════
//  ROUTES
// ═══════════════════════════════════════════════════════

// ── GET /api/health ──────────────────────────────────

server.get('/api/health', (req, res) => {
    res.json({ success: true, message: 'Kova Auth API is running.', version: '1.0.0' });
});

// ── POST /api/keys/create ────────────────────────────

server.post('/api/keys/create', authenticate, async (req, res) => {
    try {
        const { type, expiry, note, custom_key, amount } = req.body;
        const count = Math.min(Math.max(parseInt(amount) || 1, 1), 50);

        const validTypes = ['Trial', 'Standard', 'Lifetime', 'Custom'];
        const licenseType = type || 'Standard';
        if (!validTypes.includes(licenseType)) {
            return res.status(400).json({
                success: false,
                message: `Invalid type. Use: ${validTypes.join(', ')}`
            });
        }

        // Calculate expiry duration
        let expiryMs;
        if (licenseType === 'Trial')         expiryMs = 3 * 86400000;
        else if (licenseType === 'Standard') expiryMs = 30 * 86400000;
        else if (licenseType === 'Lifetime') expiryMs = 3650 * 86400000;
        else {
            expiryMs = parseExpiry(expiry);
            if (!expiryMs) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid expiry. Use days (number), or: 1s, 5d, 2m, 1y, f'
                });
            }
        }

        // Override with custom expiry if provided
        if (expiry && licenseType !== 'Custom') {
            const override = parseExpiry(expiry);
            if (override) expiryMs = override;
        }

        // Check license limit
        const user = await fbGet('users/' + req.kova.uid);
        const isPremium = user && user.plan === 'premium';

        if (!isPremium) {
            const limit = (user && user.licenseLimit) || 5;
            const apps = await fbGet('applications/' + req.kova.uid);
            let totalLicenses = 0;
            if (apps) {
                for (const aid of Object.keys(apps)) {
                    const lics = await fbGet('licenses/' + aid);
                    if (lics) totalLicenses += Object.keys(lics).length;
                }
            }
            if (totalLicenses + count > limit) {
                return res.status(403).json({
                    success: false,
                    message: `License limit would be exceeded (${totalLicenses}+${count} > ${limit}). Upgrade to premium.`
                });
            }
        }

        // Generate keys
        const created = [];
        for (let i = 0; i < count; i++) {
            const key = (count === 1 && custom_key) ? custom_key : generateLicenseKey();
            const license = {
                key,
                type: licenseType,
                note: note || '',
                expiryDate: Date.now() + expiryMs,
                createdAt: Date.now(),
                status: 'Not used'
            };

            const result = await fbPost('licenses/' + req.kova.appId, license);
            created.push({ id: result.name, ...license });
        }

        // Log activity
        if (count === 1) {
            await logActivity(req.kova.uid, 'creation',
                `License <strong>${created[0].key.substring(0, 9)}...</strong> created via API for <strong>${req.kova.appName}</strong>`,
                `Type: ${licenseType}`
            );
        } else {
            await logActivity(req.kova.uid, 'creation',
                `<strong>${count}</strong> licenses created via API for <strong>${req.kova.appName}</strong>`,
                `Type: ${licenseType}`
            );
        }

        return res.status(201).json({
            success: true,
            message: `${count} license key(s) created.`,
            data: count === 1 ? created[0] : created
        });

    } catch (err) {
        console.error('Create key error:', err);
        return res.status(500).json({ success: false, message: 'Failed to create key: ' + err.message });
    }
});

// ── DELETE /api/keys/delete ──────────────────────────

server.delete('/api/keys/delete', authenticate, async (req, res) => {
    try {
        const key = req.body.key || req.query.key;
        const licenseId = req.body.license_id || req.query.license_id;

        if (!key && !licenseId) {
            return res.status(400).json({
                success: false,
                message: 'Provide "key" or "license_id".'
            });
        }

        let targetId = null;
        let targetKey = null;

        if (licenseId) {
            const lic = await fbGet('licenses/' + req.kova.appId + '/' + licenseId);
            if (lic) {
                targetId = licenseId;
                targetKey = lic.key;
            }
        } else {
            const result = await findLicense(req.kova.appId, key);
            targetId = result.targetId;
            targetKey = key;
        }

        if (!targetId) {
            return res.status(404).json({ success: false, message: 'License key not found.' });
        }

        await fbDelete('licenses/' + req.kova.appId + '/' + targetId);

        await logActivity(req.kova.uid, 'deletion',
            `License <strong>${targetKey.substring(0, 9)}...</strong> deleted via API`,
            req.kova.appName
        );

        return res.json({
            success: true,
            message: 'License deleted.',
            data: { id: targetId, key: targetKey }
        });

    } catch (err) {
        console.error('Delete key error:', err);
        return res.status(500).json({ success: false, message: 'Failed to delete key: ' + err.message });
    }
});

// ── GET /api/keys/list ───────────────────────────────

server.get('/api/keys/list', authenticate, async (req, res) => {
    try {
        const licenses = [];
        const data = await fbGet('licenses/' + req.kova.appId);

        if (data) {
            for (const [id, lic] of Object.entries(data)) {
                licenses.push({
                    id,
                    key: lic.key,
                    type: lic.type,
                    note: lic.note || '',
                    hwid: lic.hwid || null,
                    status: lic.status,
                    banned: lic.banned || false,
                    banReason: lic.banReason || null,
                    expiryDate: lic.expiryDate,
                    createdAt: lic.createdAt,
                    activatedAt: lic.activatedAt || null,
                    expired: lic.expiryDate ? lic.expiryDate < Date.now() : false
                });
            }
        }

        licenses.sort((a, b) => b.createdAt - a.createdAt);

        return res.json({
            success: true,
            message: `${licenses.length} license(s) found.`,
            data: { application: req.kova.appName, total: licenses.length, licenses }
        });

    } catch (err) {
        console.error('List keys error:', err);
        return res.status(500).json({ success: false, message: 'Failed to list keys.' });
    }
});

// ── GET /api/keys/verify ─────────────────────────────

server.get('/api/keys/verify', authenticate, async (req, res) => {
    try {
        const { key, hwid } = req.query;
        if (!key) {
            return res.status(400).json({ success: false, message: 'Provide "key" query param.' });
        }

        const { targetId, license } = await findLicense(req.kova.appId, key);
        if (!targetId || !license) {
            return res.status(404).json({ success: false, message: 'Invalid license key.' });
        }

        if (license.banned) {
            return res.status(403).json({
                success: false,
                message: 'License is banned.',
                reason: license.banReason || null
            });
        }

        if (license.expiryDate && license.expiryDate < Date.now()) {
            return res.status(403).json({ success: false, message: 'License has expired.' });
        }

        // HWID locking
        if (hwid) {
            if (license.hwid && license.hwid !== hwid) {
                return res.status(403).json({
                    success: false,
                    message: 'HWID mismatch. License locked to another device.'
                });
            }

            if (!license.hwid) {
                const updates = { hwid, status: 'Used', activatedAt: Date.now() };
                await fbPatch('licenses/' + req.kova.appId + '/' + targetId, updates);
                Object.assign(license, updates);

                await logActivity(req.kova.uid, 'activation',
                    `License <strong>${key.substring(0, 9)}...</strong> activated on <strong>${hwid.substring(0, 8)}...</strong>`,
                    req.kova.appName
                );
            }
        }

        return res.json({
            success: true,
            message: 'License is valid.',
            data: {
                key: license.key,
                type: license.type,
                note: license.note || '',
                hwid: license.hwid || null,
                status: license.status,
                expiryDate: license.expiryDate,
                createdAt: license.createdAt,
                activatedAt: license.activatedAt || null,
                daysRemaining: license.expiryDate
                    ? Math.max(0, Math.ceil((license.expiryDate - Date.now()) / 86400000))
                    : null
            }
        });

    } catch (err) {
        console.error('Verify key error:', err);
        return res.status(500).json({ success: false, message: 'Verification failed.' });
    }
});

// ── POST /api/keys/ban ───────────────────────────────

server.post('/api/keys/ban', authenticate, async (req, res) => {
    try {
        const { key, reason } = req.body;
        if (!key) return res.status(400).json({ success: false, message: 'Provide "key".' });

        const { targetId } = await findLicense(req.kova.appId, key);
        if (!targetId) return res.status(404).json({ success: false, message: 'Key not found.' });

        await fbPatch('licenses/' + req.kova.appId + '/' + targetId, {
            banned: true, banReason: reason || null, bannedAt: Date.now()
        });

        await logActivity(req.kova.uid, 'ban',
            `License <strong>${key.substring(0, 9)}...</strong> banned via API`,
            reason || 'No reason'
        );

        return res.json({ success: true, message: 'License banned.', data: { key } });

    } catch (err) {
        console.error('Ban error:', err);
        return res.status(500).json({ success: false, message: 'Failed to ban key.' });
    }
});

// ── POST /api/keys/unban ─────────────────────────────

server.post('/api/keys/unban', authenticate, async (req, res) => {
    try {
        const { key } = req.body;
        if (!key) return res.status(400).json({ success: false, message: 'Provide "key".' });

        const { targetId } = await findLicense(req.kova.appId, key);
        if (!targetId) return res.status(404).json({ success: false, message: 'Key not found.' });

        await fbPatch('licenses/' + req.kova.appId + '/' + targetId, {
            banned: false, banReason: null, bannedAt: null
        });

        await logActivity(req.kova.uid, 'unban',
            `License <strong>${key.substring(0, 9)}...</strong> unbanned via API`,
            req.kova.appName
        );

        return res.json({ success: true, message: 'License unbanned.', data: { key } });

    } catch (err) {
        console.error('Unban error:', err);
        return res.status(500).json({ success: false, message: 'Failed to unban key.' });
    }
});

// ── POST /api/keys/reset-hwid ────────────────────────

server.post('/api/keys/reset-hwid', authenticate, async (req, res) => {
    try {
        const { key } = req.body;
        if (!key) return res.status(400).json({ success: false, message: 'Provide "key".' });

        const { targetId } = await findLicense(req.kova.appId, key);
        if (!targetId) return res.status(404).json({ success: false, message: 'Key not found.' });

        await fbPatch('licenses/' + req.kova.appId + '/' + targetId, {
            hwid: null, activatedAt: null, status: 'Not used'
        });

        await logActivity(req.kova.uid, 'reset',
            `HWID reset via API for <strong>${key.substring(0, 9)}...</strong>`,
            req.kova.appName
        );

        return res.json({ success: true, message: 'HWID reset.', data: { key } });

    } catch (err) {
        console.error('Reset HWID error:', err);
        return res.status(500).json({ success: false, message: 'Failed to reset HWID.' });
    }
});

// ═══════════════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════════════

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log('');
    console.log('  ╔══════════════════════════════════════════════╗');
    console.log('  ║   🔑  Kova Auth API — v1.0.0                ║');
    console.log(`  ║   Running on http://localhost:${PORT}           ║`);
    console.log('  ╚══════════════════════════════════════════════╝');
    console.log('');
    console.log('  Endpoints:');
    console.log('    GET    /api/health');
    console.log('    POST   /api/keys/create       (create 1 or bulk keys)');
    console.log('    DELETE /api/keys/delete        (delete by key or id)');
    console.log('    GET    /api/keys/list          (list all keys)');
    console.log('    GET    /api/keys/verify        (verify + HWID lock)');
    console.log('    POST   /api/keys/ban           (ban a key)');
    console.log('    POST   /api/keys/unban         (unban a key)');
    console.log('    POST   /api/keys/reset-hwid    (reset HWID lock)');
    console.log('');
    console.log('  Auth headers: x-owner-id, x-app-name, x-app-secret');
    console.log('');
});
