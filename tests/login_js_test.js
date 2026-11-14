// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

// Runs the login page's return-address code, the part of its inline script from
// allowedRedirectHosts to returnTo(), as the page has it.
// Run with: node --test tests/login_js_test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '../web/templates/login.html'), 'utf8');
const start = html.indexOf('    const allowedRedirectHosts = ');
const end = html.indexOf('\n    }\n', html.indexOf('    function returnTo() {')) + 6;
assert.ok(start > 0 && end > start, 'the return-address code is where this test looks for it');
const code = html.slice(start, end);

// The server fills in basePath and the allowed hosts as JavaScript values.
function page({ base = '', referrer = '', hosts = [] } = {}) {
  const context = {
    URL,
    signetBase: base,
    referrerField: { value: referrer },
    window: { location: { origin: 'https://signet.example' } },
  };
  vm.runInNewContext(code.replace('{{.AllowedRedirectHosts}}', JSON.stringify(hosts)) +
    '\nthis.returnTo = returnTo; this.safeTarget = safeTarget;', context);
  return context;
}

test('with nowhere to return to, the account page', () => {
  assert.strictEqual(page().returnTo(), '/account');
  assert.strictEqual(page({ base: '/auth' }).returnTo(), '/auth/account');
});

test('a host that is not allowed goes to the account page too', () => {
  assert.strictEqual(page({ base: '/auth', referrer: 'https://evil.example/x' }).returnTo(), '/auth/account');
  assert.strictEqual(page({ referrer: 'javascript:alert(1)' }).returnTo(), '/account');
});

test('a return address of this site, or of an allowed host, is kept', () => {
  assert.strictEqual(page({ base: '/auth', referrer: '/comments/post?id=3' }).returnTo(), '/comments/post?id=3');
  assert.strictEqual(page({ referrer: 'https://app.example.net/p', hosts: ['app.example.net'] }).returnTo(), 'https://app.example.net/p');
  assert.strictEqual(page().safeTarget('https://signet.example/x#y'), '/x#y');
});

test('a path that resolves to another host goes to the account page', () => {
  for (const referrer of ['/.//evil.example/x', '/a/..//evil.example/x', '/%2e//evil.example/x',
    '/./\\evil.example/x', 'https://signet.example/.//evil.example/x']) {
    assert.strictEqual(page({ referrer }).returnTo(), '/account', referrer);
  }
});
