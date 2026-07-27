import crypto from 'crypto';

// --- SECURE ENVIRONMENT VARIABLES (No hardcoded keys) ---
const REDIS_URL = process.env.REDIS_URL;
const REDIS_TOKEN = process.env.REDIS_TOKEN;

// Helper function to execute Redis commands via REST API securely
async function redisCommand(command, ...args) {
    const response = await fetch(REDIS_URL, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${REDIS_TOKEN}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify([command, ...args])
    });
    const data = await response.json();
    if (data.error) throw new Error(data.error);
    return data.result;
}

// Military-grade password hashing utilizing native Node.js Scrypt
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
    const [salt, hash] = storedHash.split(':');
    const derivedHash = crypto.scryptSync(password, salt, 64).toString('hex');
    return hash === derivedHash;
}

// Normalizes email inputs to guarantee @lmail.com identity & removes whitespaces
function formatLmail(email) {
    let cleanEmail = (email || "").trim().toLowerCase();
    if (!cleanEmail) throw new Error("Email cannot be empty.");
    
    // Automatically enforce Lmail domain
    if (!cleanEmail.includes('@')) {
        cleanEmail += '@lmail.com';
    } else {
        cleanEmail = cleanEmail.split('@')[0] + '@lmail.com';
    }
    return cleanEmail;
}

export default async function handler(req, res) {
    // CORS Headers for secure cross-origin interaction
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

    try {
        const { action, email, password, device_id } = req.body;
        
        // 1. Check if device is blocked by Admin
        if (device_id) {
            const isDeviceBlocked = await redisCommand("GET", `blocked_device:${device_id.trim()}`);
            if (isDeviceBlocked) {
                return res.status(403).json({ error: 'This device has been permanently blocked by the Admin.' });
            }
        }

        // --- ACTION: REGISTER (Frictionless, Secure, No Duplicates) ---
        if (action === 'register') {
            const safeEmail = formatLmail(email);
            const cleanPassword = (password || "").trim();
            
            if (cleanPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

            // STRICT DUPLICATE CHECK: Ensures no user@lmail.com is repeated
            const existingUser = await redisCommand("GET", `user:${safeEmail}`);
            if (existingUser) return res.status(400).json({ error: 'This Lmail address is already taken.' });

            // Create highly secure user profile
            const userProfile = {
                email: safeEmail,
                password_hash: hashPassword(cleanPassword),
                created_at: new Date().toISOString(),
                blocked: false,
                registered_device: device_id ? device_id.trim() : 'Unknown'
            };

            await redisCommand("SET", `user:${safeEmail}`, JSON.stringify(userProfile));
            
            // Add to global users set for Admin listing
            await redisCommand("SADD", "global:users", safeEmail);

            return res.status(200).json({ success: true, message: 'Lmail account created successfully!', email: safeEmail });
        }

        // --- ACTION: LOGIN ---
        if (action === 'login') {
            const safeEmail = formatLmail(email);
            const cleanPassword = (password || "").trim();

            const userDataStr = await redisCommand("GET", `user:${safeEmail}`);
            if (!userDataStr) return res.status(404).json({ error: 'Account not found.' });

            const userProfile = JSON.parse(userDataStr);
            if (userProfile.blocked) return res.status(403).json({ error: 'This account has been blocked by the Admin.' });

            if (!verifyPassword(cleanPassword, userProfile.password_hash)) {
                return res.status(401).json({ error: 'Invalid password.' });
            }

            // Generate secure session token (Stored in Redis for 24 hours)
            const sessionToken = crypto.randomBytes(32).toString('hex');
            await redisCommand("SETEX", `session:${sessionToken}`, 86400, safeEmail);

            return res.status(200).json({ success: true, token: sessionToken, email: safeEmail });
        }

        // --- ACTION: GET DASHBOARD (Shows connected apps) ---
        if (action === 'get_dashboard') {
            const { token } = req.body;
            if (!token) return res.status(401).json({ error: 'Unauthorized.' });

            const safeEmail = await redisCommand("GET", `session:${token.trim()}`);
            if (!safeEmail) return res.status(401).json({ error: 'Session expired or invalid.' });

            // Fetch list of 3rd party websites they signed into
            const connectedApps = await redisCommand("SMEMBERS", `user_apps:${safeEmail}`);

            return res.status(200).json({ success: true, email: safeEmail, connected_apps: connectedApps || [] });
        }

        return res.status(400).json({ error: 'Invalid action specified.' });

    } catch (error) {
        return res.status(500).json({ error: 'Internal Server Error', details: error.message });
    }
}
