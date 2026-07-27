// --- SECURE ENVIRONMENT VARIABLES ---
// Vercel will automatically inject these from your Environment Variables settings
const REDIS_URL = process.env.REDIS_URL;
const REDIS_TOKEN = process.env.REDIS_TOKEN;

// --- STRICT SECURITY: MASTER PASSWORD ---
const MASTER_PASSWORD = "Lexis-Admin-2026!";

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

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();

    try {
        const { action, target_email, admin_password } = req.body;

        // --- STRICT PASSWORD SECURITY CHECK ---
        if (!admin_password || admin_password !== MASTER_PASSWORD) {
            return res.status(403).json({ error: 'ACCESS DENIED: Invalid Admin Password.' });
        }

        // --- ACTION: LIST ALL USERS ---
        if (action === 'list_users') {
            const allEmails = await redisCommand("SMEMBERS", "global:users") || [];
            let users = [];
            
            // Fetch detailed profile for each user
            for (let email of allEmails) {
                const data = await redisCommand("GET", `user:${email}`);
                if (data) {
                    let parsed = JSON.parse(data);
                    delete parsed.password_hash; // Hide secure hash from UI
                    // Remove device ID from the payload since we removed the feature
                    if (parsed.registered_device) delete parsed.registered_device; 
                    users.push(parsed);
                }
            }
            return res.status(200).json({ success: true, users });
        }

        // --- ACTION: BLOCK/UNBLOCK USER ACCOUNT ---
        if (action === 'toggle_block_user') {
            if (!target_email) return res.status(400).json({ error: 'Missing target email.' });
            const email = target_email.trim().toLowerCase();

            const userDataStr = await redisCommand("GET", `user:${email}`);
            if (!userDataStr) return res.status(404).json({ error: 'User not found.' });

            let userProfile = JSON.parse(userDataStr);
            userProfile.blocked = !userProfile.blocked; // Toggle status
            
            await redisCommand("SET", `user:${email}`, JSON.stringify(userProfile));
            return res.status(200).json({ success: true, message: `Account block status changed to: ${userProfile.blocked}` });
        }

        return res.status(400).json({ error: 'Invalid admin action specified.' });

    } catch (error) {
        return res.status(500).json({ error: 'Internal Server Error', details: error.message });
    }
}


