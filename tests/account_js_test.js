// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

// Runs the account page's inline script against a stub DOM and a mocked fetch.
// Run with: node --test tests/account_js_test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '../web/templates/account.html'), 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
const pageScript = scripts[scripts.length - 1][1].replace('{{.Fresh}}', 'true');
// The server fills in basePath as a JavaScript string.
const scriptFor = (base) => pageScript.replaceAll('{{basePath}}', JSON.stringify(base));

function element(id) {
  const listeners = {};
  return {
    id, hidden: false, value: '', textContent: '', className: '', children: [],
    addEventListener: (name, fn) => { listeners[name] = fn; },
    listeners,
    append(...more) { this.children.push(...more); },
    replaceChildren(...more) { this.children = more; },
  };
}

const dialogIds = ['remove-dialog', 'remove-title', 'remove-text', 'remove-cancel', 'remove-confirm'];

function run({ ids, replies = [], removeButtons = [], base = '', prepare = () => {}, globals = {} }) {
  const elements = {};
  for (const id of [...ids, ...dialogIds]) elements[id] = element(id);
  const dialog = elements['remove-dialog'];
  dialog.returnValue = '';
  dialog.answer = 'remove';
  dialog.showModal = () => { dialog.returnValue = dialog.answer; dialog.listeners.close(); };
  prepare(elements);
  const calls = [];
  const reloads = { count: 0 };
  const sandbox = {
    document: {
      getElementById: (id) => elements[id] || null,
      createElement: () => element('new'),
      querySelectorAll: (selector) => (selector === '.totp-remove' ? removeButtons : []),
    },
    window: { PublicKeyCredential: function () {}, location: { href: '/account', reload() { reloads.count += 1; } } },
    JSON, Date, Promise, Math, Uint8Array, String,
    btoa: (binary) => Buffer.from(binary, 'binary').toString('base64'),
    ...globals,
    fetch: async (url, init) => {
      calls.push({ url, init });
      const reply = replies.shift();
      if (reply instanceof Error) throw reply;
      return { ok: reply.status < 400, status: reply.status, json: async () => reply.body };
    },
  };
  vm.runInNewContext(scriptFor(base), sandbox);
  return { elements, calls, reloads };
}
const passwordIds = ['message', 'password-form', 'current', 'new', 'confirm'];
const settle = () => new Promise((resolve) => setImmediate(resolve));
const submit = async (form) => {
  let stopped = false;
  await form.listeners.submit({ preventDefault: () => { stopped = true; } });
  await settle();
  return stopped;
};

test('two different new passwords are not sent', async () => {
  const { elements, calls } = run({ ids: passwordIds });
  elements.new.value = 'one-long-password';
  elements.confirm.value = 'another-long-password';
  assert.strictEqual(await submit(elements['password-form']), true);
  assert.strictEqual(calls.length, 0);
  assert.match(elements.message.textContent, /do not match/);
});

test('a change posts the fields, and success clears them', async () => {
  const { elements, calls } = run({ ids: passwordIds, replies: [{ status: 200, body: { success: true, message: 'done' } }] });
  elements.current.value = 'old-long-password';
  elements.new.value = 'new-long-password';
  elements.confirm.value = 'new-long-password';
  await submit(elements['password-form']);
  assert.strictEqual(calls[0].url, '/account');
  assert.strictEqual(calls[0].init.method, 'POST');
  assert.deepStrictEqual(JSON.parse(calls[0].init.body), { action: 'password', current: 'old-long-password', new: 'new-long-password' });
  assert.strictEqual(elements.message.textContent, 'done');
  assert.strictEqual(elements.new.value, '');
  assert.strictEqual(elements.current.value, '');
});

test('an account with no password sends an empty current one', async () => {
  const { elements, calls } = run({ ids: ['message', 'password-form', 'new', 'confirm'], replies: [{ status: 200, body: { success: true, message: 'done' } }] });
  elements.new.value = 'new-long-password';
  elements.confirm.value = 'new-long-password';
  await submit(elements['password-form']);
  assert.strictEqual(JSON.parse(calls[0].init.body).current, '');
});

test('a refusal shows its reason and keeps the fields', async () => {
  const { elements } = run({ ids: passwordIds, replies: [{ status: 400, body: { success: false, error: 'not right' } }] });
  elements.new.value = 'new-long-password';
  elements.confirm.value = 'new-long-password';
  await submit(elements['password-form']);
  assert.strictEqual(elements.message.textContent, 'not right');
  assert.strictEqual(elements.new.value, 'new-long-password');
  assert.strictEqual(elements.message.children.length, 0);
});

test('a stale sign-in offers the way back', async () => {
  const { elements } = run({ ids: passwordIds, replies: [{ status: 403, body: { success: false, error: 'sign in again' } }] });
  elements.new.value = 'new-long-password';
  elements.confirm.value = 'new-long-password';
  await submit(elements['password-form']);
  assert.strictEqual(elements.message.children[0].href, '/login?referrer=%2Faccount');
});

test('under a base path, the page posts and sends people to sign in there', async () => {
  const { elements, calls } = run({ ids: passwordIds, base: '/auth', replies: [{ status: 403, body: { success: false, error: 'sign in again' } }] });
  elements.new.value = 'new-long-password';
  elements.confirm.value = 'new-long-password';
  await submit(elements['password-form']);
  assert.strictEqual(calls[0].url, '/auth/account');
  assert.strictEqual(elements.message.children[0].href, '/auth/login?referrer=%2Fauth%2Faccount');
});

test('a network failure is reported', async () => {
  const { elements } = run({ ids: passwordIds, replies: [new Error('offline')] });
  elements.new.value = 'new-long-password';
  elements.confirm.value = 'new-long-password';
  await submit(elements['password-form']);
  assert.match(elements.message.textContent, /could not be changed/);
});

const totpIds = ['message', 'totp-begin', 'totp-finish', 'totp-label', 'totp-qr', 'totp-secret', 'totp-code', 'recovery-codes', 'recovery-list', 'recovery-done'];

test('adding a key shows the QR code and secret, and asks for a code', async () => {
  const { elements, calls } = run({ ids: totpIds, replies: [{ status: 200, body: { success: true, qr: 'data:image/png;base64,x', secret: 'ABC' } }] });
  elements['totp-finish'].hidden = true;
  elements['totp-label'].value = 'phone';
  await submit(elements['totp-begin']);
  assert.deepStrictEqual(JSON.parse(calls[0].init.body), { action: 'totp-begin', label: 'phone' });
  assert.strictEqual(elements['totp-qr'].src, 'data:image/png;base64,x');
  assert.strictEqual(elements['totp-secret'].textContent, 'ABC');
  assert.strictEqual(elements['totp-begin'].hidden, true);
  assert.strictEqual(elements['totp-finish'].hidden, false);
});

test('recovery codes stay on the page until the person says they have them', async () => {
  const { elements, calls, reloads } = run({ ids: totpIds, replies: [{ status: 200, body: { success: true, recovery_codes: ['aaaa', 'bbbb'] } }] });
  elements['recovery-codes'].hidden = true;
  elements['totp-code'].value = '123456';
  await submit(elements['totp-finish']);
  assert.deepStrictEqual(JSON.parse(calls[0].init.body), { action: 'totp-finish', code: '123456' });
  assert.strictEqual(elements['recovery-list'].textContent, 'aaaa\nbbbb');
  assert.strictEqual(elements['recovery-codes'].hidden, false);
  assert.strictEqual(reloads.count, 0);
  elements['recovery-done'].listeners.click();
  assert.strictEqual(reloads.count, 1);
});

test('a later key has no codes to show, so the page reloads', async () => {
  const { elements, reloads } = run({ ids: totpIds, replies: [{ status: 200, body: { success: true } }] });
  await submit(elements['totp-finish']);
  assert.strictEqual(reloads.count, 1);
});

test('a wrong code keeps the form and says so', async () => {
  const { elements, reloads } = run({ ids: totpIds, replies: [{ status: 400, body: { success: false, error: 'not right' } }] });
  await submit(elements['totp-finish']);
  assert.strictEqual(elements['totp-finish'].hidden, false);
  assert.strictEqual(elements.message.textContent, 'not right');
  assert.strictEqual(reloads.count, 0);
});

function removeButton() {
  const button = element('remove');
  button.closest = () => ({ dataset: { id: 'key-1', label: 'phone' } });
  return button;
}

test('removing a key asks first, and sends its ID', async () => {
  const button = removeButton();
  const { elements, calls, reloads } = run({ ids: totpIds, removeButtons: [button], replies: [{ status: 200, body: { success: true } }] });
  await button.listeners.click();
  await settle();
  assert.match(elements['remove-title'].textContent, /phone/);
  assert.deepStrictEqual(JSON.parse(calls[0].init.body), { action: 'totp-remove', id: 'key-1' });
  assert.strictEqual(reloads.count, 1);
});

test('cancelling removes nothing', async () => {
  const button = removeButton();
  const { elements, calls } = run({ ids: totpIds, removeButtons: [button] });
  elements['remove-dialog'].answer = 'cancel';
  await button.listeners.click();
  await settle();
  assert.strictEqual(calls.length, 0);
});

// The picture: a canvas that records what is drawn, and blobs of chosen sizes.
const avatarIds = ['message', 'avatar-image', 'avatar-edit', 'avatar-section', 'avatar-file', 'avatar-choose', 'avatar-remove',
  'avatar-preview-box', 'avatar-preview', 'avatar-save', 'avatar-cancel'];
function avatarPage({ replies = [], sizes = {}, bitmap = { width: 400, height: 300 } } = {}) {
  const drawn = [];
  const blobs = [];
  const page = run({
    ids: avatarIds,
    replies,
    prepare: (elements) => {
      const canvas = elements['avatar-preview'];
      canvas.width = 256;
      canvas.height = 256;
      canvas.getContext = () => ({ clearRect() {}, drawImage: (...args) => drawn.push(args) });
      canvas.toBlob = (done, type, quality) => {
        blobs.push({ type, quality });
        const size = sizes[type + (quality || '')] ?? 100;
        const bytes = Buffer.alloc(size, type === 'image/png' ? 'P' : 'J');
        done({ size, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + size) });
      };
      elements['avatar-file'].click = () => { elements['avatar-file'].clicked = true; };
      elements['avatar-image'].dataset = { identicon: 'data:image/svg+xml;base64,PATTERN' };
    },
    globals: {
      createImageBitmap: async (file) => {
        if (file === 'not an image') throw new Error('unreadable');
        return bitmap;
      },
    },
  });
  return { ...page, drawn, blobs };
}
const choose = async (elements, file) => {
  elements['avatar-file'].files = [file];
  await elements['avatar-file'].listeners.change();
  await settle();
};

test('choosing an image previews the middle square, and saving sends it as PNG', async () => {
  const { elements, calls, drawn } = avatarPage({
    replies: [{ status: 200, body: { success: true, message: 'Your picture has been changed.', avatar: '/avatar/abc' } }],
  });
  elements['avatar-remove'].hidden = true;
  elements['avatar-preview-box'].hidden = true;
  elements['avatar-choose'].listeners.click();
  assert.strictEqual(elements['avatar-file'].clicked, true);
  await choose(elements, 'photo.png');
  assert.strictEqual(elements['avatar-preview-box'].hidden, false);
  // 400x300: the 300 square from x=50, drawn over the whole canvas.
  assert.deepStrictEqual(drawn[0].slice(1), [50, 0, 300, 300, 0, 0, 256, 256]);
  assert.strictEqual(calls.length, 0, 'nothing is sent before Save');

  await elements['avatar-save'].listeners.click();
  await settle();
  const body = JSON.parse(calls[0].init.body);
  assert.strictEqual(body.action, 'avatar-set');
  assert.strictEqual(Buffer.from(body.image, 'base64').toString(), 'P'.repeat(100));
  assert.strictEqual(elements['avatar-image'].src, '/avatar/abc');
  assert.strictEqual(elements['avatar-remove'].hidden, false);
  assert.strictEqual(elements['avatar-preview-box'].hidden, true);
  assert.strictEqual(elements['avatar-section'].hidden, true, 'the controls close');
});

test('Edit opens and closes the picture controls', () => {
  const { elements } = avatarPage();
  elements['avatar-section'].hidden = true;
  let stopped = false;
  const click = () => elements['avatar-edit'].listeners.click({ preventDefault: () => { stopped = true; } });
  click();
  assert.strictEqual(elements['avatar-section'].hidden, false);
  assert.strictEqual(stopped, true, 'the link does not navigate');
  click();
  assert.strictEqual(elements['avatar-section'].hidden, true);
});

test('a large PNG is sent as JPEG, stepping the quality down to fit', async () => {
  const { elements, calls, blobs } = avatarPage({
    sizes: { 'image/png': 200000, 'image/jpeg0.85': 100000, 'image/jpeg0.7': 50000 },
    replies: [{ status: 200, body: { success: true, message: 'ok', avatar: '/avatar/def' } }],
  });
  await choose(elements, 'photo.jpg');
  await elements['avatar-save'].listeners.click();
  await settle();
  assert.deepStrictEqual(blobs.map((b) => b.type + (b.quality || '')), ['image/png', 'image/jpeg0.85', 'image/jpeg0.7']);
  assert.strictEqual(Buffer.from(JSON.parse(calls[0].init.body).image, 'base64').toString(), 'J'.repeat(50000));
});

test('an image that never fits is not sent', async () => {
  const { elements, calls } = avatarPage({
    sizes: { 'image/png': 200000, 'image/jpeg0.85': 200000, 'image/jpeg0.7': 200000, 'image/jpeg0.5': 100000 },
  });
  await choose(elements, 'noise.png');
  await elements['avatar-save'].listeners.click();
  await settle();
  assert.strictEqual(calls.length, 0);
  assert.match(elements.message.textContent, /too detailed/);
});

test('a file the browser cannot read is reported, and nothing is previewed', async () => {
  const { elements, calls } = avatarPage();
  elements['avatar-preview-box'].hidden = true;
  await choose(elements, 'not an image');
  assert.strictEqual(elements['avatar-preview-box'].hidden, true);
  assert.match(elements.message.textContent, /not an image/);
  assert.strictEqual(calls.length, 0);
});

test('a refused picture shows the reason and keeps the preview', async () => {
  const { elements } = avatarPage({ replies: [{ status: 403, body: { success: false, error: 'Sign in again' } }] });
  await choose(elements, 'photo.png');
  await elements['avatar-save'].listeners.click();
  await settle();
  assert.strictEqual(elements['avatar-preview-box'].hidden, false);
  assert.match(elements.message.textContent, /Sign in again/);
});

test('removing the picture asks first, then clears it', async () => {
  const { elements, calls } = avatarPage({ replies: [{ status: 200, body: { success: true, message: 'Your picture has been removed.' } }] });
  elements['avatar-image'].src = '/avatar/abc';
  elements['avatar-remove'].listeners.click();
  await settle();
  await settle();
  assert.strictEqual(JSON.parse(calls[0].init.body).action, 'avatar-remove');
  assert.strictEqual(elements['avatar-image'].src, 'data:image/svg+xml;base64,PATTERN', 'the pattern is back');
  assert.strictEqual(elements['avatar-remove'].hidden, true);
});

test('cancelling the removal keeps the picture', async () => {
  const { elements, calls } = avatarPage();
  elements['remove-dialog'].answer = 'cancel';
  elements['avatar-remove'].listeners.click();
  await settle();
  assert.strictEqual(calls.length, 0);
});
