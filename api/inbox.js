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

function verifyPassword(password, storedHash) {
    const [salt, hash] = storedHash.split(':');
    const derivedHash = crypto.scryptSync(password, salt, 64).toString('hex');
    return hash === derivedHash;
}

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();

    try {
        const { action, email, password } = req.body;

        if (!email || !password) return res.status(401).json({ error: 'Authentication required.' });

        let safeEmail = email.trim().toLowerCase();
        if (!safeEmail.includes('@')) safeEmail += '@lmail.com';
        else safeEmail = safeEmail.split('@')[0] + '@lmail.com';

        // STRICT SECURITY: Verify User identity
        const userDataStr = await redisCommand("GET", `user:${safeEmail}`);
        if (!userDataStr) return res.status(404).json({ error: 'Account not found.' });

        const userProfile = JSON.parse(userDataStr);
        if (userProfile.blocked) return res.status(403).json({ error: 'Account blocked.' });

        if (!verifyPassword(password.trim(), userProfile.password_hash)) {
            return res.status(401).json({ error: 'Invalid password.' });
        }

        // --- ACTION: SAVE PROXY (Triggered by frontend Residential IP) ---
        if (action === 'save_proxy') {
            const { proxyAddress, proxyToken } = req.body;
            await redisCommand("SADD", `user_proxies:${safeEmail}`, `${proxyAddress}::${proxyToken}`);
            return res.status(200).json({ success: true });
        }

        // --- ACTION: SAVE EMAIL (Permanently store mail fetched by frontend) ---
        if (action === 'save_email') {
            const { emailData } = req.body;
            // Prevent duplicates
            const isProcessed = await redisCommand("GET", `processed_msg:${emailData.id}`);
            if (!isProcessed) {
                await redisCommand("LPUSH", `inbox:${safeEmail}`, JSON.stringify(emailData));
                await redisCommand("SETEX", `processed_msg:${emailData.id}`, 604800, "true"); // cache for 7 days
            }
            return res.status(200).json({ success: true });
        }

        // --- ACTION: FETCH INBOX (Retrieve permanent emails and tokens) ---
        if (action === 'get_inbox') {
            // Return tokens so the frontend can check for new mail directly
            const userProxies = await redisCommand("SMEMBERS", `user_proxies:${safeEmail}`) || [];
            
            // Return permanent emails
            const emailsRaw = await redisCommand("LRANGE", `inbox:${safeEmail}`, 0, 49); // Keep last 50
            let emails = (emailsRaw || []).map(str => JSON.parse(str));
            emails.sort((a, b) => new Date(b.date) - new Date(a.date));

            return res.status(200).json({ success: true, proxies: userProxies, emails: emails });
        }
        
        // --- ACTION: CLEAR INBOX ---
        if (action === 'clear_inbox') {
            await redisCommand("DEL", `inbox:${safeEmail}`);
            return res.status(200).json({ success: true, message: 'Inbox cleared.' });
        }

        return res.status(400).json({ error: 'Invalid inbox action.' });

    } catch (error) {
        return res.status(500).json({ error: 'Internal Server Error', details: error.message });
    }
}


