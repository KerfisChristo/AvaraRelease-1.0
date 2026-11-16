const assert = require('node:assert/strict');
const { after, before, test } = require('node:test');
const { createApp } = require('../server');

const validSubmission = {
  name: 'Test User',
  email: 'test@example.com',
  message: 'A test inquiry',
  captchaAnswer: '7'
};

async function startServer(options) {
  const server = createApp(options).listen(0);
  await new Promise(resolve => server.once('listening', resolve));
  const address = server.address();
  return {
    server,
    post: body => fetch(`http://127.0.0.1:${address.port}/api/contact`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
  };
}

let server;
let post;

before(async () => {
  ({ server, post } = await startServer({
    env: {
      MS_TENANT_ID: 'tenant-id',
      MS_CLIENT_ID: 'client-id',
      MS_REFRESH_TOKEN: 'refresh-token'
    },
    fetchImpl: async (url, options) => {
      if (String(url).includes('/oauth2/v2.0/token')) {
        assert.equal(options.method, 'POST');
        return new Response(JSON.stringify({
          access_token: 'access-token',
          expires_in: 3600
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      assert.equal(url, 'https://graph.microsoft.com/v1.0/me/sendMail');
      const request = JSON.parse(options.body);
      assert.equal(request.message.toRecipients[0].emailAddress.address, 'website@avara.is');
      assert.equal(request.message.replyTo, undefined);
      assert.match(request.message.body.content, /Netfang \(óstaðfest\): test@example.com/);
      assert.match(request.message.body.content, /A test inquiry/);
      return new Response(null, { status: 202 });
    }
  }));
});

after(async () => {
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
});

test('health endpoint responds successfully', async () => {
  const response = await fetch(`http://127.0.0.1:${server.address().port}/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
});

test('serves the public homepage', async () => {
  const response = await fetch(`http://127.0.0.1:${server.address().port}/`);
  assert.equal(response.status, 200);
  assert.match(await response.text(), /id="contactForm"/);
});

test('rejects invalid email addresses', async () => {
  const response = await post({ ...validSubmission, email: 'not-an-email' });
  assert.equal(response.status, 400);
});

test('rejects an incorrect captcha answer', async () => {
  const response = await post({ ...validSubmission, captchaAnswer: '8' });
  assert.equal(response.status, 400);
});

test('sends valid inquiries through Microsoft Graph', async () => {
  const response = await post(validSubmission);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
});
