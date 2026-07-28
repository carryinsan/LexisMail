import crypto from 'crypto';

// Securely read keys from Vercel Environment Variables
const REDIS_URL = process.env.REDIS_URL;
const REDIS_TOKEN = process.env.REDIS_TOKEN;

async function redisCommand(command, ...args) {
    if (!REDIS_URL || !REDIS_TOKEN) {
        throw new Error("Server configuration error: Redis keys are missing.");
    }

    const response = await fetch(REDIS_URL, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${REDIS_TOKEN}`, 'Content-Type': 'application/json' },
        body: JSON.stringify([command, ...args])
    });
    const data = await response.json();
    if (data.error) throw new Error(data.error);
    return data.result;
}

// Function to verify password hash
function verifyPassword(password, storedHash) {
    const [salt, hash] = storedHash.split(':');
    const derivedHash = crypto.scryptSync(password, salt, 64).toString('hex');
    return hash === derivedHash;
}

export default async function handler(req, res) {
    // CORS Headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();

    try {
        const { action, email, password } = req.body;

        if (!email || !password) {
            return res.status(401).json({ error: 'Authentication required.' });
        }

        // Format email to ensure strict match
        let safeEmail = email.trim().toLowerCase();
        if (!safeEmail.includes('@')) safeEmail += '@lmail.com';
        else safeEmail = safeEmail.split('@')[0] + '@lmail.com';

        // 1. STRICT SECURITY: Verify User identity before showing inbox
        const userDataStr = await redisCommand("GET", `user:${safeEmail}`);
        if (!userDataStr) return res.status(404).json({ error: 'Account not found.' });

        const userProfile = JSON.parse(userDataStr);
        if (userProfile.blocked) return res.status(403).json({ error: 'Account blocked.' });

        if (!verifyPassword(password.trim(), userProfile.password_hash)) {
            return res.status(401).json({ error: 'Invalid password.' });
        }

        // --- ACTION: FETCH INBOX ---
        if (action === 'get_inbox') {
            // Retrieve the emails beamed in by our Stealth Bot
            const redisKey = `inbox:${safeEmail}`;
            const emailsRaw = await redisCommand("LRANGE", redisKey, 0, -1);
            
            // Parse the JSON strings back into objects
            const emails = (emailsRaw || []).map(str => JSON.parse(str));
            
            return res.status(200).json({ success: true, emails: emails });
        }
        
        // --- ACTION: DELETE EMAIL ---
        if (action === 'clear_inbox') {
            const redisKey = `inbox:${safeEmail}`;
            await redisCommand("DEL", redisKey);
            return res.status(200).json({ success: true, message: 'Inbox cleared.' });
        }

        return res.status(400).json({ error: 'Invalid inbox action.' });

    } catch (error) {
        return res.status(500).json({ error: 'Internal Server Error', details: error.message });
    }
}


