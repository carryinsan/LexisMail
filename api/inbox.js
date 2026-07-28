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

        // --- ACTION: GENERATE SECURE GHOST PROXY ---
        if (action === 'generate_proxy') {
            // Generates a professional looking address like 'lmail.node.4f8a@wuuvo.com'
            // We use wuuvo.com as it is supported by the free 1secmail API and doesn't trigger filters
            const randomHex = crypto.randomBytes(3).toString('hex');
            const proxyAddress = `lmail.node.${randomHex}@wuuvo.com`;
            
            // Save this mapping so we know this proxy belongs to this specific user
            await redisCommand("SADD", `user_proxies:${safeEmail}`, proxyAddress);
            
            return res.status(200).json({ success: true, proxy: proxyAddress });
        }

        // --- ACTION: FETCH INBOX (Pulls from Ghost API & Redis) ---
        if (action === 'get_inbox') {
            const redisKey = `inbox:${safeEmail}`;
            
            // 1. Check Ghost API for new messages sent to any of this user's proxies
            const userProxies = await redisCommand("SMEMBERS", `user_proxies:${safeEmail}`) || [];
            
            for (let proxy of userProxies) {
                const [login, domain] = proxy.split('@');
                try {
                    // Poll the external API
                    const checkRes = await fetch(`https://www.1secmail.com/api/v1/?action=getMessages&login=${login}&domain=${domain}`);
                    const messages = await checkRes.json();

                    for (let msg of messages) {
                        // Avoid duplicates
                        const isProcessed = await redisCommand("GET", `processed_msg:${msg.id}`);
                        if (!isProcessed) {
                            const fullMsgRes = await fetch(`https://www.1secmail.com/api/v1/?action=readMessage&login=${login}&domain=${domain}&id=${msg.id}`);
                            const fullMsg = await fullMsgRes.json();

                            const emailData = {
                                id: msg.id,
                                from: fullMsg.from,
                                subject: fullMsg.subject || "No Subject",
                                body: fullMsg.textBody || fullMsg.htmlBody || "No Content",
                                date: fullMsg.date,
                                delivered_to: safeEmail // Mask it so it looks like it went to user@lmail.com
                            };

                            // Save to secure Redis Inbox
                            await redisCommand("LPUSH", redisKey, JSON.stringify(emailData));
                            // Mark processed (expires in 7 days)
                            await redisCommand("SETEX", `processed_msg:${msg.id}`, 604800, "true");
                        }
                    }
                } catch (e) {
                    console.error("Ghost API Sync Error:", e);
                }
            }

            // 2. Retrieve all synced emails from Redis
            const emailsRaw = await redisCommand("LRANGE", redisKey, 0, 49); // Keep last 50
            let emails = (emailsRaw || []).map(str => JSON.parse(str));
            
            // Sort newest first
            emails.sort((a, b) => new Date(b.date) - new Date(a.date));

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


