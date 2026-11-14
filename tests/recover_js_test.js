// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

// Runs the inline script of the recovery and registration pages against a stub
// DOM and a mocked fetch.
// Run with: node --test tests/recover_js_test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

for (const page of ['recover', 'register']) {
const html = fs.readFileSync(path.join(__dirname, `../web/templates/${page}.html`), 'utf8');
const pageScript = /<script>([\s\S]*?)<\/script>/.exec(html)[1];
// The server fills in basePath as a JavaScript string.
const scriptFor = (base) => pageScript.replaceAll('{{basePath}}', JSON.stringify(base));
const route = `/${page}`;

function run(hash, replies = [], base = '') {
  const elements = {};
  for (const id of ['request-form', 'reset-form', 'link-error', 'intro', 'token', 'password', 'confirm']) {
    const listeners = {};
    elements[id] = {
      id,
      hidden: id === 'reset-form' || id === 'link-error',
      value: '',
      textContent: '',
      addEventListener: (name, fn) => { listeners[name] = fn; },
      listeners,
    };
  }
  const calls = [];
  const replaced = [];
  const windowListeners = {};
  const sandbox = {
    document: { getElementById: (id) => elements[id] || null },
    window: {
      location: { hash, pathname: base + route },
      history: { replaceState: (...args) => replaced.push(args) },
      addEventListener: (name, fn) => { windowListeners[name] = fn; },
    },
    URLSearchParams,
    fetch: async (url, init) => {
      calls.push({ url, init });
      const reply = replies.shift();
      if (reply instanceof Error) throw reply;
      return { ok: reply.status < 400, status: reply.status, json: async () => reply.body };
    },
  };
  vm.runInNewContext(scriptFor(base), sandbox);
  // Pasting a link into the open page changes only the fragment.
  const paste = (next) => {
    sandbox.window.location.hash = next;
    windowListeners.hashchange();
  };
  return { elements, calls, replaced, paste };
}
const settle = () => new Promise((resolve) => setImmediate(resolve));

test(`${page}: ` + 'with no token in the address, the page asks for an address and calls nothing', () => {
  const { elements, calls, replaced } = run('');
  assert.strictEqual(calls.length, 0);
  assert.strictEqual(replaced.length, 0);
  assert.strictEqual(elements['request-form'].hidden, false);
  assert.strictEqual(elements['reset-form'].hidden, true);
});

test(`${page}: ` + 'under a base path, the link is checked there and the address bar keeps the base', async () => {
  const { calls, replaced } = run('#token=abc', [{ status: 200, body: { success: true } }], '/auth');
  assert.deepStrictEqual(replaced[0][2], '/auth' + route);
  await settle();
  assert.strictEqual(calls[0].url, '/auth' + route);
});

test(`${page}: ` + 'a good link clears the address bar, is checked, and only then asks for a password', async () => {
  const { elements, calls, replaced } = run('#token=abc_-1', [{ status: 200, body: { success: true } }]);
  assert.deepStrictEqual(replaced[0][2], route);
  assert.strictEqual(elements['reset-form'].hidden, true);
  assert.strictEqual(elements['request-form'].hidden, true);
  await settle();
  assert.strictEqual(calls[0].url, route);
  assert.strictEqual(calls[0].init.method, 'POST');
  assert.strictEqual(calls[0].init.headers.Accept, 'application/json');
  assert.strictEqual(calls[0].init.body.get('token'), 'abc_-1');
  assert.strictEqual(calls[0].init.body.has('password'), false);
  assert.strictEqual(elements['reset-form'].hidden, false);
  assert.strictEqual(elements['request-form'].hidden, true);
  assert.strictEqual(elements.token.value, 'abc_-1');
});

test(`${page}: ` + 'a dead link is refused before any password is asked for', async () => {
  const { elements } = run('#token=dead', [{ status: 400, body: { success: false, error: 'expired link' } }]);
  await settle();
  assert.strictEqual(elements['reset-form'].hidden, true);
  assert.strictEqual(elements['request-form'].hidden, false);
  assert.strictEqual(elements['link-error'].hidden, false);
  assert.strictEqual(elements['link-error'].textContent, 'expired link');
  assert.strictEqual(elements.token.value, '');
});

test(`${page}: ` + 'a network failure says so and asks for no password', async () => {
  const { elements } = run('#token=abc', [new Error('offline')]);
  await settle();
  assert.strictEqual(elements['reset-form'].hidden, true);
  assert.match(elements['link-error'].textContent, /could not be checked/);
});

test(`${page}: ` + 'a link pasted into the open page is checked without a reload', async () => {
  const { elements, calls, replaced, paste } = run('', [{ status: 200, body: { success: true } }]);
  assert.strictEqual(calls.length, 0);
  paste('#token=pasted');
  assert.deepStrictEqual(replaced[0][2], route);
  await settle();
  assert.strictEqual(calls[0].init.body.get('token'), 'pasted');
  assert.strictEqual(elements['reset-form'].hidden, false);
  assert.strictEqual(elements['request-form'].hidden, true);
});

test(`${page}: ` + 'after a dead link, a good one pasted in clears the refusal', async () => {
  const { elements, paste } = run('#token=dead', [
    { status: 400, body: { success: false, error: 'This link has expired.' } },
    { status: 200, body: { success: true } },
  ]);
  await settle();
  assert.strictEqual(elements['link-error'].hidden, false);
  paste('#token=fresh');
  await settle();
  assert.strictEqual(elements['link-error'].hidden, true);
  assert.strictEqual(elements['reset-form'].hidden, false);
  assert.strictEqual(elements.token.value, 'fresh');
});

test(`${page}: ` + 'a fragment that is not a token is ignored', () => {
  const { calls, replaced } = run('#token=<script>');
  assert.strictEqual(calls.length, 0);
  assert.strictEqual(replaced.length, 0);
});

test(`${page}: ` + 'two different passwords, or none, are not submitted', () => {
  const { elements } = run('');
  const submit = () => {
    let stopped = false;
    elements['reset-form'].listeners.submit({ preventDefault: () => { stopped = true; } });
    return stopped;
  };
  elements.password.value = 'one-password';
  elements.confirm.value = 'another-password';
  assert.strictEqual(submit(), true);
  assert.match(elements['link-error'].textContent, /do not match/);
  elements.password.value = '';
  elements.confirm.value = '';
  assert.strictEqual(submit(), true);
  elements.password.value = 'same-password';
  elements.confirm.value = 'same-password';
  assert.strictEqual(submit(), false);
});
}
