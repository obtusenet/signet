// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

// Tests the browser script's encoding against a mocked fetch and
// navigator.credentials.  Run with: node --test tests/webauthn_js_test.js
// This checks shapes and field names only; a real browser and authenticator
// remain the final check.
const test = require('node:test');
const assert = require('node:assert');

const { WebAuthn, WebAuthnHelpers, WebAuthnUI } = require('../web/static/js/webauthn.js');

const b64 = (s) => Buffer.from(s).toString('base64url');
const buf = (s) => {
  const b = Buffer.from(s);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
};
const text = (ab) => Buffer.from(ab).toString();

// Installs a scripted fetch; returns the recorded calls.
function mockFetch(replies) {
  const calls = [];
  global.fetch = async (url, init) => {
    calls.push({ url, init });
    const { status = 200, body } = replies.shift();
    return { ok: status < 400, status, json: async () => body };
  };
  return calls;
}

function mockCredentials(methods) {
  Object.defineProperty(global, 'navigator', {
    value: { credentials: methods },
    configurable: true,
  });
}

test('base64url round trip keeps every byte', () => {
  const all = Uint8Array.from({ length: 256 }, (_, i) => i).buffer;
  const encoded = WebAuthnHelpers.arrayBufferToBase64url(all);
  assert.ok(!/[+/=]/.test(encoded));
  assert.deepStrictEqual(new Uint8Array(WebAuthnHelpers.base64urlToArrayBuffer(encoded)), new Uint8Array(all));
});

test('register decodes options, reads response properties, and sends the ceremony', async () => {
  const calls = mockFetch([
    {
      body: {
        success: true,
        ceremony: 'cer-1',
        options: {
          publicKey: {
            rp: { id: 'signet.example', name: 'Signet' },
            challenge: b64('chal'),
            user: { id: b64('uid'), name: 'a@b', displayName: 'a@b' },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            excludeCredentials: [{ type: 'public-key', id: b64('old') }],
          },
        },
      },
    },
    { body: { success: true, credential: { id: 'abc', label: 'mine' } } },
  ]);

  let seen;
  mockCredentials({
    create: async ({ publicKey }) => {
      seen = publicKey;
      return {
        id: b64('new'),
        rawId: buf('new'),
        type: 'public-key',
        authenticatorAttachment: 'cross-platform',
        // Attributes, as on AuthenticatorAttestationResponse: there is no getClientDataJSON().
        response: {
          clientDataJSON: buf('client'),
          attestationObject: buf('object'),
          getTransports: () => ['usb'],
        },
      };
    },
  });

  const result = await new Promise((resolve, reject) =>
    WebAuthnUI.register('mine', null, resolve, reject)
  );
  assert.strictEqual(result.label, 'mine');

  assert.strictEqual(text(seen.challenge), 'chal');
  assert.strictEqual(text(seen.user.id), 'uid');
  assert.strictEqual(text(seen.excludeCredentials[0].id), 'old');

  assert.strictEqual(calls[0].url, '/webauthn/register/start');
  assert.match(calls[1].url, /^\/webauthn\/register\/finish\?/);
  const query = new URLSearchParams(calls[1].url.split('?')[1]);
  assert.strictEqual(query.get('ceremony'), 'cer-1');
  assert.strictEqual(query.get('label'), 'mine');
  assert.ok(!query.has('email'), 'the address must not come from the client');

  // The body is the credential object itself, not a string wrapping it.
  const body = JSON.parse(calls[1].init.body);
  assert.strictEqual(body.rawId, b64('new'));
  assert.strictEqual(body.response.clientDataJSON, b64('client'));
  assert.strictEqual(body.response.attestationObject, b64('object'));
  assert.deepStrictEqual(body.response.transports, ['usb']);
});

test('an invite travels in the header, never in a URL', async () => {
  const calls = mockFetch([
    {
      body: {
        success: true,
        ceremony: 'c',
        options: { publicKey: { challenge: b64('c'), user: { id: b64('u') } } },
      },
    },
    { body: { success: true, credential: {} } },
  ]);
  mockCredentials({
    create: async () => ({
      id: 'x',
      rawId: buf('x'),
      type: 'public-key',
      response: { clientDataJSON: buf('c'), attestationObject: buf('o') },
    }),
  });

  await new Promise((resolve, reject) => WebAuthnUI.register('k', 'SECRET-TOKEN', resolve, reject));
  for (const call of calls) {
    assert.strictEqual(call.init.headers['X-Signet-Invite'], 'SECRET-TOKEN');
    assert.ok(!call.url.includes('SECRET-TOKEN'));
  }
});

test('login decodes options, handles a null user handle, and sends the ceremony', async () => {
  const calls = mockFetch([
    {
      body: {
        success: true,
        ceremony: 'cer-2',
        options: {
          publicKey: {
            challenge: b64('chal'),
            rpId: 'signet.example',
            allowCredentials: [{ type: 'public-key', id: b64('cred') }],
          },
        },
      },
    },
    { body: { success: true } },
  ]);

  let seen;
  mockCredentials({
    get: async ({ publicKey }) => {
      seen = publicKey;
      return {
        id: b64('cred'),
        rawId: buf('cred'),
        type: 'public-key',
        response: {
          clientDataJSON: buf('client'),
          authenticatorData: buf('auth'),
          signature: buf('sig'),
          userHandle: null,
        },
      };
    },
  });

  await new Promise((resolve, reject) => WebAuthnUI.login('a@b', resolve, reject));

  assert.strictEqual(text(seen.challenge), 'chal');
  assert.strictEqual(text(seen.allowCredentials[0].id), 'cred');

  const query = new URLSearchParams(calls[1].url.split('?')[1]);
  assert.strictEqual(query.get('email'), 'a@b');
  assert.strictEqual(query.get('ceremony'), 'cer-2');
  const body = JSON.parse(calls[1].init.body);
  assert.strictEqual(body.response.signature, b64('sig'));
  assert.strictEqual(body.response.authenticatorData, b64('auth'));
  assert.strictEqual(body.response.userHandle, null);
});

test('the script reads its base path from its own tag, and is empty without one', () => {
  const src = require('node:fs').readFileSync(`${__dirname}/../web/static/js/webauthn.js`, 'utf8');
  const loaded = (currentScript) => require('node:vm').runInNewContext(`${src}\nWebAuthn.basePath`, { document: { currentScript } });
  assert.strictEqual(loaded({ dataset: { basePath: '/auth' } }), '/auth');
  assert.strictEqual(loaded({ dataset: {} }), '');
  assert.strictEqual(loaded(null), '');
});

test('every request goes under the base path', async () => {
  WebAuthn.basePath = '/auth';
  try {
    const calls = mockFetch([{ body: { success: true, user: 'a@b', credentials: [] } }]);
    await WebAuthn.listCredentials();
    assert.strictEqual(calls[0].url, '/auth/webauthn/credentials');
  } finally {
    WebAuthn.basePath = '';
  }
});

test('a failure status becomes an error carrying the message and status', async () => {
  mockFetch([{ status: 401, body: { success: false, error: 'sign in first' } }]);
  await assert.rejects(WebAuthn.listCredentials(), (error) => {
    assert.strictEqual(error.message, 'sign in first');
    assert.strictEqual(error.status, 401);
    return true;
  });
});

test('a failed ceremony reaches onError', async () => {
  mockFetch([{ status: 401, body: { success: false, error: 'security key sign-in failed' } }]);
  const error = await new Promise((resolve, reject) => WebAuthnUI.login('a@b', reject, resolve));
  assert.strictEqual(error.message, 'security key sign-in failed');
});

// Runs the keys page's own inline script against a small stand-in for the DOM.
function openPage(hash, replies, base = '') {
  const html = require('node:fs').readFileSync(`${__dirname}/../web/templates/webauthn.html`, 'utf8');
  // The server fills in basePath as a JavaScript string.
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1].replaceAll('{{basePath}}', JSON.stringify(base));

  const element = () => ({
    hidden: true, textContent: '', value: '', href: '', className: '', children: [], listeners: {},
    addEventListener(kind, fn) { this.listeners[kind] = fn; },
    append(...nodes) { this.children.push(...nodes); },
    replaceChildren(...nodes) { this.children = nodes; },
    showModal() { this.open = true; },
    close(value) {
      this.open = false;
      if (value !== undefined) this.returnValue = value;
      this.listeners.close();
    },
  });
  const elements = {};
  const calls = mockFetch(replies);
  const context = {
    WebAuthn, WebAuthnUI, URLSearchParams, encodeURIComponent, Date,
    history: { replaceState() {} },
    document: {
      getElementById: (id) => (elements[id] ??= element()),
      createElement: element,
    },
    window: {
      location: { hash, pathname: base + '/webauthn/keys' },
      PublicKeyCredential: function () {},
    },
  };
  require('node:vm').runInNewContext(script, context);
  return { elements, calls };
}
const settle = () => new Promise((resolve) => setTimeout(resolve, 10));

test('a live invite shows the form, and asking does not send it in a URL', async () => {
  const { elements, calls } = openPage('#invite=tok', [{ body: { success: true } }]);
  assert.strictEqual(elements.enroll.hidden, true, 'no form before the server answers');
  await settle();
  assert.strictEqual(elements.enroll.hidden, false);
  assert.strictEqual(calls[0].url, '/webauthn/invite');
  assert.strictEqual(calls[0].init.method, 'GET');
  assert.strictEqual(calls[0].init.headers['X-Signet-Invite'], 'tok');
});

test('under a base path, the keys page sends people to sign in there', async () => {
  const { elements } = openPage('#invite=spent', [{ status: 401, body: { success: false, error: 'this invite is not valid or has expired' } }], '/auth');
  await settle();
  assert.strictEqual(elements.back.href, '/auth/login');
});

test('a used invite is refused without showing the form', async () => {
  const { elements } = openPage('#invite=spent', [{ status: 401, body: { success: false, error: 'this invite is not valid or has expired' } }]);
  await settle();
  assert.strictEqual(elements.enroll.hidden, true);
  assert.strictEqual(elements.message.hidden, false);
  assert.match(elements.message.textContent, /already been used or has expired/);
  assert.strictEqual(elements.back.href, '/login');
});

test('another refusal, or no answer, shows no form either', async () => {
  const locked = openPage('#invite=tok', [{ status: 403, body: { success: false, error: 'this account cannot enroll security keys' } }]);
  await settle();
  assert.strictEqual(locked.elements.enroll.hidden, true);
  assert.strictEqual(locked.elements.message.textContent, 'this account cannot enroll security keys');

  const down = openPage('#invite=tok', [{ status: 502 }]);
  await settle();
  assert.strictEqual(down.elements.enroll.hidden, true);
  assert.strictEqual(down.elements.message.hidden, false);
});

function signedInWithKeys(count, extra = []) {
  const credentials = Array.from({ length: count }, (_, i) => ({ id: `id${i}`, label: `key${i}`, created_at: '2026-11-06T00:00:00Z' }));
  return openPage('', [{ body: { success: true, user: 'a@b', credentials } }, ...extra]);
}
const pressRemove = async (page) => {
  page.elements.keys.children[0].children[1].listeners.click();
  await settle();
};
const dialogText = (page) => [page.elements['remove-title'].textContent,
  ...page.elements['remove-text'].children.map((p) => p.textContent)].join('\n');

test('removing a key asks first, in the page dialog, and sends nothing until answered', async () => {
  const page = signedInWithKeys(2, [{ body: { success: true, signed_out: true } }]);
  await settle();
  await pressRemove(page);
  assert.strictEqual(page.elements['remove-dialog'].open, true);
  assert.match(dialogText(page), /^Remove "key0"\?/);
  assert.match(dialogText(page), /no longer sign in to this account/);
  assert.match(dialogText(page), /signs the account out everywhere, including here/);
  assert.doesNotMatch(dialogText(page), /only security key/);
  assert.strictEqual(page.calls.length, 1, 'no DELETE before an answer');

  page.elements['remove-confirm'].listeners.click();
  await settle();
  assert.strictEqual(page.elements['remove-dialog'].open, false);
  assert.strictEqual(page.calls[1].init.method, 'DELETE');
  assert.match(page.elements.message.textContent, /signed out everywhere/);
  assert.strictEqual(page.elements.enroll.hidden, true);
  assert.strictEqual(page.elements.keys.hidden, true);
  assert.strictEqual(page.elements.back.href, '/login?referrer=%2Fwebauthn%2Fkeys');
});

test('removing the only key says so', async () => {
  const page = signedInWithKeys(1);
  await settle();
  await pressRemove(page);
  assert.match(dialogText(page), /only security key/);
});

test('Cancel and Escape delete nothing', async () => {
  const page = signedInWithKeys(2);
  await settle();
  await pressRemove(page);
  page.elements['remove-cancel'].listeners.click();
  await settle();
  // Escape closes the dialog with no value of its own.
  await pressRemove(page);
  page.elements['remove-dialog'].close();
  await settle();
  assert.strictEqual(page.calls.length, 1, 'no DELETE was sent');
  assert.strictEqual(page.elements.enroll.hidden, false);
});
