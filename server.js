const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const querystring = require('querystring');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { logEvent, closeMongo } = require('./lib/mongo');

function loadDotEnvLite() {
    try {
        const envPath = path.join(__dirname, '.env');
        if (!fs.existsSync(envPath)) return;

        const raw = fs.readFileSync(envPath, 'utf8');
        for (const line of raw.split(/\r?\n/)) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;
            const eq = trimmed.indexOf('=');
            if (eq <= 0) continue;

            const key = trimmed.slice(0, eq).trim();
            let val = trimmed.slice(eq + 1).trim();
            if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
                val = val.slice(1, -1);
            }
            if (process.env[key] === undefined) process.env[key] = val;
        }
    } catch {}
}

loadDotEnvLite();
const app = express();

app.use(cookieParser());

function ensureSid(req, res) {
    let sid = req.cookies.sid;
    if (!sid) {
        sid = crypto.randomBytes(16).toString('hex');
        res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax' });
    }
    return sid;
}

app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = 'https://connect.dga.or.th';
const REDIRECT_URI = `http://localhost:${PORT}/callback`;
const SCOPE = 'openid citizen_id given_name family_name email phone_number';

function makeState() {
    return crypto.randomBytes(16).toString('hex');
}

const DGA_CLIENT_ID = (process.env.DGA_CLIENT_ID || '9e5c84d2-a51b-4686-b8a6-e52782a792b6').trim();
const DGA_CLIENT_SECRET = (process.env.DGA_CLIENT_SECRET || 'fXEBc3LZa3r').trim();

function escapeHtml(str = '') {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function renderTemplate(fileName, vars = {}) {
    const filePath = path.join(__dirname, 'public', fileName);
    let html = fs.readFileSync(filePath, 'utf8');
    for (const [k, v] of Object.entries(vars)) {
        const pattern = new RegExp(`\\{\\{\\s*${k}\\s*\\}\\}`, 'g');
        html = html.replace(pattern, v);
    }
    return html;
}

function getAuthHeader(consumerKey, consumerSecret) {
    let currentString = consumerSecret.trim();
    for (let i = 0; i < 7; i++) {
        let contentToHash = currentString + 'EGA'; 
        currentString = crypto.createHash('md5').update(contentToHash).digest('hex');
    }
    const finalHash = currentString;
    const authString = `${consumerKey.trim()}:${finalHash}`;
    const base64Auth = Buffer.from(authString).toString('base64'); 
    return `Basic ${base64Auth}`; 
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    const sid = ensureSid(req, res);
    const clientId = DGA_CLIENT_ID;

    const state = makeState();
    res.cookie('oidc_state', state, { httpOnly: true, sameSite: 'lax' });

    const authUrl = `${BASE_URL}/connect/authorize?` + querystring.stringify({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: REDIRECT_URI,
        scope: SCOPE,
        state
    });
    
    logEvent('login_redirect', req, { sid, state });
    res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
    const sid = ensureSid(req, res);
    const { code, state } = req.query;
    const clientId = DGA_CLIENT_ID;
    const clientSecret = DGA_CLIENT_SECRET;

    if (!code) {
        logEvent('callback_error', req, { sid, reason: 'no_code' });
        return res.status(400).send('Error: No code received');
    }

    const expectedState = req.cookies.oidc_state;
    if (!expectedState || !state || String(state) !== String(expectedState)) {
        logEvent('callback_error', req, { sid, reason: 'invalid_state' });
        return res.status(400).send('Error: Invalid state');
    }

    res.clearCookie('oidc_state');

    try {
        const authHeaderValue = getAuthHeader(clientId, clientSecret);

        const tokenResponse = await axios.post(
            `${BASE_URL}/connect/token`, 
            querystring.stringify({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: REDIRECT_URI
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': authHeaderValue
                }
            }
        );

        const { access_token, id_token } = tokenResponse.data;

        const userInfoResponse = await axios.get(`${BASE_URL}/connect/userinfo`, {
            headers: { 'Authorization': `Bearer ${access_token}` }
        });

        const userData = userInfoResponse.data;
        res.cookie('id_token', id_token, { httpOnly: true });

	    const displayName =
	        userData.name ||
	        ((userData.given_name || '') + ' ' + (userData.family_name || '')).trim() ||
	        null;

	    logEvent('callback_success', req, {
	        sid,
	        user: {
	            sub: userData.sub || null,
	            citizen_id: userData.citizen_id || null,
	            email: userData.email || null,
	            name: displayName,
	            given_name: userData.given_name || null,
	            family_name: userData.family_name || null,
	        },
	        tokens: { access_token, id_token },
	    });

	    const displayNameText = displayName || '-';
        const html = renderTemplate('success.html', {
	        name: escapeHtml(displayNameText),
            email: escapeHtml(userData.email || '-'),
            citizen_id: escapeHtml(userData.citizen_id || '-'),
            raw_json: escapeHtml(JSON.stringify(userData, null, 2))
        });
        res.send(html);

    } catch (error) {
        logEvent('callback_error', req, { sid, reason: 'exception', message: error.message });
        console.error('Error:', error.message);
        res.status(500).send(`
            <div style="font-family:sans-serif; text-align:center; padding:50px;">
                <h1 style="color:red;">Login Failed</h1>
                <p>${error.message}</p>
                <a href="/">กลับหน้าหลัก</a>
            </div>
        `);
    }
});


app.get('/logout', (req, res) => {
    const sid = ensureSid(req, res);
    const id_token = req.cookies.id_token;
    res.clearCookie('id_token');
    logEvent('logout', req, { sid });

    const logoutUrl = `${BASE_URL}/connect/endsession?` + querystring.stringify({
        id_token_hint: id_token,
        post_logout_redirect_uri: `http://localhost:${PORT}/`
    });
    res.redirect(logoutUrl);
});

process.on('SIGINT', async () => {
    await closeMongo();
    process.exit(0);
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});