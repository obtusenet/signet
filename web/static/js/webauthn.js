// Copyright (c) 2026 Obtuse Networking LLC
// SPDX-License-Identifier: MIT

/**
 * WebAuthn client library for Signet authentication.
 * Options arrive with binary fields as base64url strings; the browser API needs
 * them as ArrayBuffers, and its answers go back as base64url JSON (WebAuthn L2
 * §5.1.3 and §5.1.4 name the response fields read below).
 */
const WebAuthnHelpers = {
  /** Convert a base64url string to an ArrayBuffer. */
  base64urlToArrayBuffer(base64url) {
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  },

  /** Convert an ArrayBuffer to a base64url string. */
  arrayBufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  },

  /** Decode the id of each credential descriptor in a list. */
  decodeDescriptors(list) {
    return (list || []).map((d) => ({ ...d, id: this.base64urlToArrayBuffer(d.id) }));
  },

  /** Server creation options to what navigator.credentials.create() takes. */
  creationOptions(options) {
    const pk = options.publicKey;
    return {
      ...pk,
      challenge: this.base64urlToArrayBuffer(pk.challenge),
      user: { ...pk.user, id: this.base64urlToArrayBuffer(pk.user.id) },
      excludeCredentials: this.decodeDescriptors(pk.excludeCredentials),
    };
  },

  /** Server request options to what navigator.credentials.get() takes. */
  requestOptions(options) {
    const pk = options.publicKey;
    return {
      ...pk,
      challenge: this.base64urlToArrayBuffer(pk.challenge),
      allowCredentials: this.decodeDescriptors(pk.allowCredentials),
    };
  },

  /** A created credential as the JSON the server parses. */
  attestationJSON(credential) {
    return {
      id: credential.id,
      rawId: this.arrayBufferToBase64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      response: {
        clientDataJSON: this.arrayBufferToBase64url(credential.response.clientDataJSON),
        attestationObject: this.arrayBufferToBase64url(credential.response.attestationObject),
        transports: credential.response.getTransports ? credential.response.getTransports() : [],
      },
    };
  },

  /** An assertion as the JSON the server parses. */
  assertionJSON(assertion) {
    const r = assertion.response;
    return {
      id: assertion.id,
      rawId: this.arrayBufferToBase64url(assertion.rawId),
      type: assertion.type,
      authenticatorAttachment: assertion.authenticatorAttachment,
      response: {
        clientDataJSON: this.arrayBufferToBase64url(r.clientDataJSON),
        authenticatorData: this.arrayBufferToBase64url(r.authenticatorData),
        signature: this.arrayBufferToBase64url(r.signature),
        userHandle: r.userHandle ? this.arrayBufferToBase64url(r.userHandle) : null,
      },
    };
  },
};

/** Calls to signet's WebAuthn endpoints. */
const WebAuthn = {
  /**
   * Where signet's routes are: the page's script tag carries the instance's
   * base_path as data-base-path, empty at the root.
   */
  basePath: (typeof document !== 'undefined' && document.currentScript
    && document.currentScript.dataset.basePath) || '',

  /** POST or fetch JSON; a failure status becomes an Error with the server's message. */
  async request(url, { method = 'POST', body, invite } = {}) {
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (invite) headers['X-Signet-Invite'] = invite;

    const response = await fetch(this.basePath + url, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });

    let data = {};
    try {
      data = await response.json();
    } catch (e) {
      // A proxy error page, for example; the status is still meaningful.
    }
    if (!response.ok || data.success === false) {
      const error = new Error(data.error || `Request failed (${response.status})`);
      error.status = response.status;
      throw error;
    }
    return data;
  },

  /** Ask whether an invite can still enroll a key, without spending it. */
  checkInvite(invite) {
    return this.request('/webauthn/invite', { method: 'GET', invite });
  },

  /** Begin enrollment for the signed-in account, or for the invite's account. */
  beginRegistration(invite) {
    return this.request('/webauthn/register/start', { invite });
  },

  /** Finish enrollment. */
  finishRegistration(ceremony, label, credentialJSON, invite) {
    const params = new URLSearchParams({ ceremony, label: label || 'Default' });
    return this.request(`/webauthn/register/finish?${params}`, { body: credentialJSON, invite });
  },

  /** Begin a security-key login. */
  beginLogin(email) {
    const params = new URLSearchParams({ email });
    return this.request(`/webauthn/authenticate/start?${params}`);
  },

  /** Finish a security-key login. */
  finishLogin(email, ceremony, assertionJSON) {
    const params = new URLSearchParams({ email, ceremony });
    return this.request(`/webauthn/authenticate/finish?${params}`, { body: assertionJSON });
  },

  /** List the signed-in user's credentials. */
  listCredentials() {
    return this.request('/webauthn/credentials', { method: 'GET' });
  },

  /** Delete one of the signed-in user's credentials.  This signs the account out everywhere. */
  deleteCredential(credentialId) {
    return this.request(`/webauthn/credentials/${encodeURIComponent(credentialId)}`, { method: 'DELETE' });
  },
};

/** The two browser ceremonies, start to finish. */
const WebAuthnUI = {
  /**
   * Enroll a security key.  With an invite the key goes on the invite's
   * account; otherwise it goes on the signed-in account.
   */
  async register(label, invite, onSuccess, onError) {
    try {
      const { options, ceremony } = await WebAuthn.beginRegistration(invite);
      const credential = await navigator.credentials.create({
        publicKey: WebAuthnHelpers.creationOptions(options),
      });
      const { credential: stored } = await WebAuthn.finishRegistration(
        ceremony,
        label,
        WebAuthnHelpers.attestationJSON(credential),
        invite
      );
      onSuccess(stored);
    } catch (error) {
      onError(error);
    }
  },

  /** Sign in with a security key. */
  async login(email, onSuccess, onError) {
    try {
      const { options, ceremony } = await WebAuthn.beginLogin(email);
      const assertion = await navigator.credentials.get({
        publicKey: WebAuthnHelpers.requestOptions(options),
      });
      await WebAuthn.finishLogin(email, ceremony, WebAuthnHelpers.assertionJSON(assertion));
      onSuccess();
    } catch (error) {
      onError(error);
    }
  },
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { WebAuthn, WebAuthnHelpers, WebAuthnUI };
}
