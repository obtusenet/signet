// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

// Runs the login page's second-step code, askForCode() and askForStep(), as the
// page has it, against a stub DOM.
// Run with: node --test tests/login_steps_js_test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '../web/templates/login.html'), 'utf8');
const start = html.indexOf('    function askForCode(');
const end = html.indexOf('    // Handle password login form submission');
assert.ok(start > 0 && end > start, 'the step code is where this test looks for it');
const code = html.slice(start, end);

function element(tag, id) {
  return {
    tag, id, hidden: false, value: '', textContent: '', children: [], focused: false, submitted: false,
    focus() { this.focused = true; },
    appendChild(child) { this.children.push(child); },
    submit() { this.submitted = true; },
  };
}

function page({ base = '', referrer = '/next' } = {}) {
  const elements = {};
  for (const id of ['sign-in-methods', 'code-pending', 'code-form', 'code', 'code-label', 'code-hint']) {
    elements[id] = element('div', id);
  }
  elements['code-form'].hidden = true;
  elements['code-label'].textContent = 'Code from your authenticator';
  const body = element('body');
  const context = {
    signetBase: base,
    referrerField: { value: referrer },
    hideMessages() {},
    document: {
      body,
      getElementById: (id) => elements[id],
      createElement: (tag) => element(tag),
    },
  };
  vm.runInNewContext(code + '\nthis.askForStep = askForStep;', context);
  return { context, elements, body };
}

test('a code step shows the code form with its token', () => {
  const { context, elements } = page();
  context.askForStep('tok', 'code');
  assert.strictEqual(elements['code-form'].hidden, false);
  assert.strictEqual(elements['sign-in-methods'].hidden, true);
  assert.strictEqual(elements['code-pending'].value, 'tok');
  assert.strictEqual(elements['code-label'].textContent, 'Code from your authenticator');
  assert.strictEqual(elements['code-hint'].hidden, false);
  assert.ok(elements.code.focused);
});

test('a mailed PIN uses the same form, asking for the PIN', () => {
  const { context, elements } = page();
  context.askForStep('tok', 'mail');
  assert.strictEqual(elements['code-form'].hidden, false);
  assert.strictEqual(elements['code-pending'].value, 'tok');
  assert.match(elements['code-label'].textContent, /PIN/);
  assert.strictEqual(elements['code-hint'].hidden, true, 'no recovery-code hint for a PIN');
});

test('adding a second factor posts the token for the server to draw the page', () => {
  const { context, elements, body } = page({ base: '/auth', referrer: '/app' });
  context.askForStep('tok', 'enrol');
  assert.strictEqual(elements['code-form'].hidden, true);
  assert.strictEqual(body.children.length, 1);
  const form = body.children[0];
  assert.strictEqual(form.method, 'POST');
  assert.strictEqual(form.action, '/auth/login');
  assert.ok(form.submitted);
  const fields = Object.fromEntries(form.children.map((input) => [input.name, input.value]));
  assert.deepStrictEqual(fields, { pending: 'tok', referrer: '/app' });
  assert.ok(form.children.every((input) => input.type === 'hidden'));
});

test('both sign-in replies hand any second step to askForStep', () => {
  const calls = html.match(/if \(data\.pending\) \{\s*askForStep\(data\.pending, data\.step \|\| 'code'\);/g) || [];
  assert.strictEqual(calls.length, 2, 'the password and the PIN replies');
  assert.ok(!/data\.totp_required/.test(html), 'no branch on totp_required alone');
});
