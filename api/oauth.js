import crypto from 'crypto';

// --- SECURE ENVIRONMENT VARIABLES (No hardcoded keys) ---
const REDIS_URL = process.env.REDIS_URL;
const REDIS_TOKEN = process.env.REDIS_TOKEN;

async function redisCommand(command, ...args) {
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
        const { action, email, password, app_name, app_url } = req.body;

        // --- ACTION: AUTHORIZE (Third Party App requests login) ---
        if (action === 'authorize') {
            // Trim inputs and enforce domain
            let safeEmail = (email || "").trim().toLowerCase();
            if (!safeEmail.includes('@')) safeEmail += '@lmail.com';
            else safeEmail = safeEmail.split('@')[0] + '@lmail.com';
            
            const cleanPassword = (password || "").trim();
            const cleanAppName = (app_name || "Unknown App").trim();
            const cleanAppUrl = (app_url || "#").trim();

            // 1. Verify User exists and credentials are correct
            const userDataStr = await redisCommand("GET", `user:${safeEmail}`);
            if (!userDataStr) return res.status(404).json({ error: 'Lmail account not found.' });

            const userProfile = JSON.parse(userDataStr);
            if (userProfile.blocked) return res.status(403).json({ error: 'Account blocked.' });

            if (!verifyPassword(cleanPassword, userProfile.password_hash)) {
                return res.status(401).json({ error: 'Invalid password.' });
            }

            // 2. Log this app connection so it shows on the user's Lmail Dashboard (app.html)
            const appData = JSON.stringify({ name: cleanAppName, url: cleanAppUrl, connected_at: new Date().toISOString() });
            await redisCommand("SADD", `user_apps:${safeEmail}`, appData);

            // 3. Generate OAuth Access Token for the third-party app
            const oauthToken = crypto.randomBytes(40).toString('hex');
            
            // Store token mapping in Redis for 1 hour
            await redisCommand("SETEX", `oauth_token:${oauthToken}`, 3600, safeEmail);

            return res.status(200).json({ 
                success: true, 
                message: 'Successfully authorized!',
                access_token: oauthToken,
                redirect_url: cleanAppUrl
            });
        }

        // --- ACTION: VERIFY (Third Party App backend verifies the token) ---
        if (action === 'verify_token') {
            const { access_token } = req.body;
            if (!access_token) return res.status(400).json({ error: 'Missing access token.' });

            const verifiedEmail = await redisCommand("GET", `oauth_token:${access_token.trim()}`);
            if (!verifiedEmail) return res.status(401).json({ error: 'Token invalid or expired.' });

            return res.status(200).json({ success: true, user: { email: verifiedEmail } });
        }

    } catch (error) {
        return res.status(500).json({ error: 'Internal Server Error', details: error.message });
    }
}
