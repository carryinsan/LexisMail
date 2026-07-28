import crypto from 'crypto';

const REDIS_URL = process.env.REDIS_URL;
const REDIS_TOKEN = process.env.REDIS_TOKEN;

async function redisCommand(command, ...args) {
    if (!REDIS_URL || !REDIS_TOKEN) throw new Error("Server configuration error: Redis keys missing.");
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

        const userDataStr = await redisCommand("GET", `user:${safeEmail}`);
        if (!userDataStr) return res.status(404).json({ error: 'Account not found.' });

        const userProfile = JSON.parse(userDataStr);
        if (userProfile.blocked) return res.status(403).json({ error: 'Account blocked.' });
        if (!verifyPassword(password.trim(), userProfile.password_hash)) return res.status(401).json({ error: 'Invalid password.' });

        // --- ACTION: GENERATE TROJAN RELAY NODE ---
        if (action === 'generate_proxy') {
            const base = "thestarsofstarsptpn";
            let trojanBase = base[0];
            
            // Mathematically injects dots without creating illegal consecutive dots
            for (let i = 1; i < base.length; i++) {
                if (Math.random() > 0.5) trojanBase += ".";
                trojanBase += base[i];
            }
            const trojanEmail = `${trojanBase}@gmail.com`;

            // Save the exact dot-mapping to Redis so the Google Script knows who this belongs to (Expires in 7 days)
            await redisCommand("SETEX", `trojan:${trojanEmail}`, 604800, safeEmail);
            
            return res.status(200).json({ success: true, proxy: trojanEmail });
        }

        // --- ACTION: FETCH INBOX ---
        if (action === 'get_inbox') {
            const emailsRaw = await redisCommand("LRANGE", `inbox:${safeEmail}`, 0, 49);
            let emails = (emailsRaw || []).map(str => JSON.parse(str));
            return res.status(200).json({ success: true, emails: emails });
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


