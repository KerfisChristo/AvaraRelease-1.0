# Avara public contact service

This small Render service serves only the public homepage and its contact endpoint. Contact submissions generate a notification only to `website@avara.is`; the sender address is included as unverified text and is not used as `Reply-To`. The service does not send email to the visitor, and no forwarding is configured.

## Microsoft Graph setup

The Entra app is single-tenant and uses delegated `Mail.Send` only. It must not be granted mailbox-reading or shared-mailbox Send As permissions.

1. In the app registration, enable **Allow public client flows** (device code flow).
2. Add **Microsoft Graph → Delegated permissions → Mail.Send**. Do not add application permissions.
3. Sign in as `website@avara.is` and consent to the requested send-only scope.
4. On a machine with Node.js 18+, run:

   ```powershell
   node setup/get-refresh-token.js <tenant-id> <client-id>
   ```

   Complete Microsoft's device sign-in as `website@avara.is`. The script saves the refresh token to `.env.local`; that file is git-ignored. Never commit or share it.
5. In Render, set `MS_TENANT_ID`, `MS_CLIENT_ID`, and `MS_REFRESH_TOKEN` from `.env.local` as secret environment variables. Do not paste the token into chat or source control.
6. Send a test inquiry and confirm the notification arrives only at `website@avara.is`.

Delegated refresh tokens can expire or be revoked. If submissions begin returning an error after a token expires, rerun the device sign-in and replace `MS_REFRESH_TOKEN` in Render.
