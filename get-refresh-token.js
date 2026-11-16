const fs = require('fs');
const path = require('path');

const [tenantId, clientId, expectedEmail = 'website@avara.is'] = process.argv.slice(2);
if (!tenantId || !clientId) {
  console.error('Usage: node setup/get-refresh-token.js <tenant-id> <client-id> [mailbox-email]');
  process.exit(1);
}

const tokenEndpoint = `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`;
const deviceCodeEndpoint = `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/devicecode`;
const scope = 'https://graph.microsoft.com/Mail.Send offline_access openid profile';

function getSignedInEmail(idToken) {
  const claims = idToken?.split('.')[1];
  if (!claims) {
    return undefined;
  }
  return JSON.parse(Buffer.from(claims, 'base64url').toString('utf8')).preferred_username;
}

async function main() {
  const deviceResponse = await fetch(deviceCodeEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: clientId, scope })
  });
  const deviceData = await deviceResponse.json();
  if (!deviceResponse.ok) {
    throw new Error(`Microsoft device authorization failed: ${deviceData.error || deviceResponse.status}`);
  }

  console.log(deviceData.message);
  const deadline = Date.now() + deviceData.expires_in * 1000;
  let interval = Math.max(Number(deviceData.interval) || 5, 5);

  while (Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, interval * 1000));
    const tokenResponse = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: clientId,
        device_code: deviceData.device_code
      })
    });
    const tokenData = await tokenResponse.json();

    if (tokenResponse.ok) {
      const signedInEmail = getSignedInEmail(tokenData.id_token);
      if (!signedInEmail || signedInEmail.toLowerCase() !== expectedEmail.toLowerCase()) {
        throw new Error(`Sign in as ${expectedEmail}; the completed sign-in was not for that mailbox.`);
      }
      if (!tokenData.refresh_token) {
        throw new Error('Microsoft did not return a refresh token. Check offline_access consent.');
      }

      const outputPath = path.join(__dirname, '..', '.env.local');
      fs.writeFileSync(
        outputPath,
        `MS_TENANT_ID=${tenantId}\nMS_CLIENT_ID=${clientId}\nMS_REFRESH_TOKEN=${tokenData.refresh_token}\n`,
        { mode: 0o600 }
      );
      console.log(`Refresh token saved to ${outputPath}. Copy its values directly into Render environment settings; do not share or commit this file.`);
      return;
    }

    if (tokenData.error === 'authorization_pending') {
      continue;
    }
    if (tokenData.error === 'slow_down') {
      interval += 5;
      continue;
    }
    throw new Error(`Microsoft device authorization failed: ${tokenData.error || tokenResponse.status}`);
  }

  throw new Error('Microsoft device authorization expired; run the setup command again.');
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
