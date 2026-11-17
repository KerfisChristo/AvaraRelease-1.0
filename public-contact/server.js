const express = require('express');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

const NOTIFICATION_MAILBOX = 'avara@avara.is';
const GRAPH_SCOPE = 'https://graph.microsoft.com/Mail.Send offline_access';

function createApp({ env = process.env, fetchImpl = fetch } = {}) {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '10kb' }));

  const allowedOrigins = new Set(
    (env.ALLOWED_ORIGINS || '').split(',').map(origin => origin.trim()).filter(Boolean)
  );
  app.use('/api/contact', (req, res, next) => {
    const origin = req.get('Origin');
    if (origin && allowedOrigins.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
      }
    } else if (req.method === 'OPTIONS') {
      return res.sendStatus(403);
    } else if (origin && allowedOrigins.size > 0) {
      return res.status(403).json({ ok: false, error: 'Origin not allowed.' });
    }
    return next();
  });

  const contactLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, error: 'Of margar tilraunir. Reyndu aftur eftir smástund.' }
  });

  let accessToken;
  let accessTokenExpiresAt = 0;
  let refreshToken = env.MS_REFRESH_TOKEN;

  async function getAccessToken() {
    if (accessToken && Date.now() < accessTokenExpiresAt - 60_000) {
      return accessToken;
    }

    if (!env.MS_TENANT_ID || !env.MS_CLIENT_ID || !refreshToken) {
      throw new Error('Microsoft Graph authentication is not configured.');
    }

    const tokenResponse = await fetchImpl(
      `https://login.microsoftonline.com/${encodeURIComponent(env.MS_TENANT_ID)}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: env.MS_CLIENT_ID,
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          scope: GRAPH_SCOPE
        })
      }
    );
    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error('Microsoft token refresh failed:', tokenData.error || tokenResponse.status);
      throw new Error('Microsoft Graph authentication failed.');
    }

    accessToken = tokenData.access_token;
    accessTokenExpiresAt = Date.now() + Number(tokenData.expires_in || 3600) * 1000;
    if (tokenData.refresh_token) {
      refreshToken = tokenData.refresh_token;
    }

    return accessToken;
  }

  async function sendContactEmail({ name, email, message }) {
    const token = await getAccessToken();
    const graphResponse = await fetchImpl('https://graph.microsoft.com/v1.0/me/sendMail', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        message: {
          subject: 'Ný fyrirspurn á vefsíðu Avara — staðfesta þarf sendanda',
          body: {
            contentType: 'Text',
            content: `Ný fyrirspurn frá vefsíðunni Avara.\nNetfang sendanda er ekki staðfest — farðu varlega með tengla og viðhengi.\n\nNafn: ${name}\nNetfang (óstaðfest): ${email}\n\nSkilaboð:\n${message}`
          },
          toRecipients: [{ emailAddress: { address: NOTIFICATION_MAILBOX } }]
        },
        saveToSentItems: false
      })
    });

    if (!graphResponse.ok) {
      const errorData = await graphResponse.json().catch(() => ({}));
      console.error('Microsoft Graph sendMail failed:', errorData.error?.code || graphResponse.status);
      throw new Error('Microsoft Graph could not send the contact email.');
    }
  }

  app.get('/health', (_req, res) => res.json({ ok: true }));

  app.post('/api/contact', contactLimiter, async (req, res) => {
    const { name, email, message, captchaAnswer } = req.body || {};
    if (typeof name !== 'string' || typeof email !== 'string' || typeof message !== 'string') {
      return res.status(400).json({ ok: false, error: 'Fylltu út nafn, netfang og skilaboð.' });
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim();
    const cleanMessage = message.trim();
    if (!cleanName || cleanName.length > 200 ||
        !cleanEmail || cleanEmail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) ||
        !cleanMessage || cleanMessage.length > 4000) {
      return res.status(400).json({ ok: false, error: 'Athugaðu að upplýsingarnar séu rétt útfylltar.' });
    }

    if (captchaAnswer !== '7') {
      return res.status(400).json({ ok: false, error: 'Rangt svar við öryggisspurningu, reyndu aftur.' });
    }

    try {
      await sendContactEmail({ name: cleanName, email: cleanEmail, message: cleanMessage });
      return res.json({ ok: true });
    } catch (error) {
      console.error('Contact email failed:', error.message);
      return res.status(503).json({
        ok: false,
        error: 'Ekki tókst að senda skilaboðin. Reyndu aftur síðar.'
      });
    }
  });

  app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
  return app;
}

if (require.main === module) {
  const env = { ...process.env };
  const secretFile = '/etc/secrets/avara-contact-api.env';
  if (fs.existsSync(secretFile)) {
    const secretLines = fs.readFileSync(secretFile, 'utf8').split(/\r?\n/);
    for (const line of secretLines) {
      const match = /^(MS_TENANT_ID|MS_CLIENT_ID|MS_REFRESH_TOKEN)=(.+)$/.exec(line);
      if (match && !env[match[1]]) {
        env[match[1]] = match[2];
      }
    }
  }

  const port = process.env.PORT || 3000;
  const app = createApp({ env });
  app.listen(port, () => {
    console.log(`Avara public site listening on port ${port}`);
    if (!env.MS_TENANT_ID || !env.MS_CLIENT_ID || !env.MS_REFRESH_TOKEN) {
      console.warn('Microsoft Graph is not configured; contact submissions will return an error.');
    }
  });
}

module.exports = { createApp };
