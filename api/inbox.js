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

        // --- ACTION: GENERATE CORPORATE GHOST PROXY ---
        if (action === 'generate_proxy') {
            // 1. Fetch available rotating domains from the Mail.gw API
            const domainRes = await fetch('https://api.mail.gw/domains?page=1');
            const domainData = await domainRes.json();
            
            if (!domainData['hydra:member'] || domainData['hydra:member'].length === 0) {
                throw new Error("Proxy node servers are currently full. Please try again in a minute.");
            }
            
            const activeDomain = domainData['hydra:member'][0].domain;
            
            // 2. Generate cryptographically random account credentials
            const randomHex = crypto.randomBytes(4).toString('hex');
            const proxyAddress = `node.${randomHex}@${activeDomain}`;
            const proxyPassword = crypto.randomBytes(12).toString('hex');

            // 3. Create the inbox physically on the external server
            const createRes = await fetch('https://api.mail.gw/accounts', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ address: proxyAddress, password: proxyPassword })
            });

            if (!createRes.ok) throw new Error("Failed to register corporate node on network.");

            // 4. Secure an Access Token for fetching mail later
            const tokenRes = await fetch('https://api.mail.gw/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ address: proxyAddress, password: proxyPassword })
            });
            
            const tokenData = await tokenRes.json();
            const proxyToken = tokenData.token;

            // 5. Save mapping in Redis as Address::Token
            await redisCommand("SADD", `user_proxies:${safeEmail}`, `${proxyAddress}::${proxyToken}`);
            
            return res.status(200).json({ success: true, proxy: proxyAddress });
        }

        // --- ACTION: FETCH INBOX (Pulls from Ghost API & Redis) ---
        if (action === 'get_inbox') {
            const redisKey = `inbox:${safeEmail}`;
            
            // 1. Check Ghost API for new messages sent to any of this user's proxies
            const userProxies = await redisCommand("SMEMBERS", `user_proxies:${safeEmail}`) || [];
            
            for (let proxyData of userProxies) {
                // Split the stored string back into email and token
                const [proxyAddress, proxyToken] = proxyData.split('::');
                if (!proxyToken) continue;

                try {
                    // Fetch list of messages using the secure token
                    const checkRes = await fetch('https://api.mail.gw/messages', {
                        headers: { 'Authorization': `Bearer ${proxyToken}` }
                    });
                    
                    if (!checkRes.ok) continue; // Skip if token expired or server error
                    const messagesData = await checkRes.json();
                    const messages = messagesData['hydra:member'] || [];

                    for (let msg of messages) {
                        // Avoid downloading duplicates
                        const isProcessed = await redisCommand("GET", `processed_msg:${msg.id}`);
                        if (!isProcessed) {
                            // Fetch the full email payload
                            const fullMsgRes = await fetch(`https://api.mail.gw/messages/${msg.id}`, {
                                headers: { 'Authorization': `Bearer ${proxyToken}` }
                            });
                            const fullMsg = await fullMsgRes.json();

                            // Determine body (Text or HTML fallback)
                            let bodyContent = "No Content Available.";
                            if (fullMsg.text) {
                                bodyContent = fullMsg.text;
                            } else if (fullMsg.html && fullMsg.html.length > 0) {
                                bodyContent = fullMsg.html[0];
                            }

                            const emailData = {
                                id: msg.id,
                                from: fullMsg.from.address,
                                subject: fullMsg.subject || "No Subject",
                                body: bodyContent,
                                date: fullMsg.createdAt,
                                delivered_to: safeEmail // Mask it for the UI
                            };

                            // Save to secure Redis Inbox
                            await redisCommand("LPUSH", redisKey, JSON.stringify(emailData));
                            // Mark processed (expires in 7 days to keep Redis clean)
                            await redisCommand("SETEX", `processed_msg:${msg.id}`, 604800, "true");
                        }
                    }
                } catch (e) {
                    console.error("Node API Sync Error for", proxyAddress, e);
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


