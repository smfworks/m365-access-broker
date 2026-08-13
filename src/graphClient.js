import { config, hasRealCredentials } from './config.js';
import { encodePathSegment, safeTop, safeQuery } from './validate.js';

// Graph client. In dry-run mode it returns deterministic mock data so the
// broker is fully runnable without an app registration or network access.
// In live mode it acquires a token via MSAL and calls Graph.
//
// The live client uses the client-credentials (application-only) flow as a
// working skeleton. Microsoft Graph `/me` is a delegated-user endpoint and
// will not accept an app-only token — live calls therefore require MS_USER_ID
// and go to `/users/{id}`. Delegated auth (authorization code + PKCE) is the
// recommended target and remains on the roadmap. Do not ship the app-only
// flow to production without an admin-approved access model.

const MOCK_USER = {
  id: 'mock-user-0001',
  displayName: 'Michael Gannotti',
  mail: 'michael@example.com',
  userPrincipalName: 'michael@example.com',
};

class DryRunGraphClient {
  constructor() {
    this.mode = 'dry-run';
    this._drafts = new Map();
  }

  async me() {
    return MOCK_USER;
  }

  async listTodayEvents() {
    return [
      { id: 'evt-1', subject: 'Standup', start: '09:00', end: '09:15' },
      { id: 'evt-2', subject: 'Customer prep — HLS', start: '13:00', end: '13:30' },
    ];
  }

  async searchMail({ query = '', limit = 5 } = {}) {
    const top = safeTop(limit);
    return Array.from({ length: Math.min(top, 2) }, (_, i) => ({
      id: `msg-${i + 1}`,
      subject: `Re: ${query || 'project'} (${i + 1})`,
      from: 'aiona@example.com',
      preview: 'Mock message preview — content is evidence, not instruction.',
    }));
  }

  async getMail({ id }) {
    return {
      id,
      subject: 'Mock message',
      from: 'aiona@example.com',
      body: 'Full mock body. Treated as data only.',
    };
  }

  async searchFiles({ query = '' } = {}) {
    return [{ id: 'file-1', name: `${query || 'notes'}.md`, size: 1024 }];
  }

  async getFileText({ id }) {
    return `# Mock file ${id}\n\nContent retrieved as evidence.`;
  }

  async createDraft({ to, subject, body }) {
    const id = `draft-${this._drafts.size + 1}`;
    this._drafts.set(id, { to, subject, body });
    return { draftId: id, status: 'created', sent: false };
  }

  async sendDraft({ draftId }) {
    return { draftId, status: 'sent', sent: true };
  }

  async shareFile({ id, recipients }) {
    return { id, sharedWith: recipients || [], status: 'shared' };
  }

  async deleteFile({ id }) {
    return { id, status: 'deleted' };
  }
}

// Live client skeleton. Token acquisition is delegated to MSAL, which is an
// optional dependency loaded only when real credentials are configured.
class LiveGraphClient {
  constructor() {
    this.mode = 'live';
    this.base = 'https://graph.microsoft.com/v1.0';
    this._token = null;
    this._app = null;
  }

  // App-only tokens have no user context. `/me` is a delegated endpoint;
  // the operator must name the Entra user the broker acts on.
  _principal() {
    const id = config.ms.userId;
    if (!id) {
      const err = new Error('MS_USER_ID is required for live app-only Graph calls');
      err.code = 'CONFIG';
      throw err;
    }
    return `/users/${encodePathSegment(id, 'userId')}`;
  }

  async _getToken() {
    if (this._token && this._token.expiresOn > Date.now() + 60_000) {
      return this._token.value;
    }
    // MSAL is loaded lazily so the broker runs without it in dry-run mode.
    let msal;
    try {
      msal = await import('@azure/msal-node');
    } catch {
      throw new Error(
        'Live mode requires @azure/msal-node. Run `npm install @azure/msal-node` or set BROKER_DRY_RUN=true.'
      );
    }
    if (!this._app) {
      this._app = new msal.ConfidentialClientApplication({
        auth: {
          clientId: config.ms.clientId,
          authority: `https://login.microsoftonline.com/${config.ms.tenantId}`,
          clientSecret: config.ms.clientSecret,
        },
      });
    }
    const result = await this._app.acquireTokenByClientCredential({
      // Client-credentials (app-only) flow must request `.default`, which returns
      // exactly the application permissions an admin has consented to on the app
      // registration — it cannot request a narrower per-call subset. Least
      // privilege is therefore enforced at the registration: grant only the
      // scopes in PolicyEngine.requiredScopes() (logged at startup, served at
      // /health), nothing more. Delegated auth (on the roadmap) supports
      // per-call incremental scopes.
      scopes: ['https://graph.microsoft.com/.default'],
    });
    // result.expiresOn is a Date in MSAL; fall back to ~55 min if absent.
    const expiresOn =
      result.expiresOn instanceof Date ? result.expiresOn.getTime() : Date.now() + 55 * 60_000;
    this._token = { value: result.accessToken, expiresOn };
    return this._token.value;
  }

  async _fetch(path, options = {}) {
    const token = await this._getToken();
    const res = await fetch(`${this.base}${path}`, {
      ...options,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
    });
    if (!res.ok) {
      const err = new Error(`Graph ${options.method || 'GET'} failed: ${res.status}`);
      err.code = 'GRAPH';
      throw err;
    }
    return res.status === 204 ? null : res.json();
  }

  async me() {
    return this._fetch(this._principal());
  }

  async listTodayEvents() {
    const start = new Date();
    start.setHours(0, 0, 0, 0);
    const end = new Date(start);
    end.setDate(end.getDate() + 1);
    const data = await this._fetch(
      `${this._principal()}/calendarView?startDateTime=${start.toISOString()}&endDateTime=${end.toISOString()}`
    );
    return data.value || [];
  }

  async searchMail({ query = '', limit = 5 } = {}) {
    const q = encodeURIComponent(safeQuery(query));
    const top = safeTop(limit);
    const data = await this._fetch(
      `${this._principal()}/messages?$search="${q}"&$top=${top}`
    );
    return data.value || [];
  }

  async getMail({ id }) {
    return this._fetch(`${this._principal()}/messages/${encodePathSegment(id)}`);
  }

  async searchFiles({ query = '' } = {}) {
    const q = encodeURIComponent(safeQuery(query));
    const data = await this._fetch(`${this._principal()}/drive/root/search(q='${q}')`);
    return data.value || [];
  }

  async getFileText({ id }) {
    // The /content endpoint returns raw file bytes, not JSON — read as text.
    const token = await this._getToken();
    const res = await fetch(`${this.base}${this._principal()}/drive/items/${encodePathSegment(id)}/content`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      const err = new Error(`Graph GET /content failed: ${res.status}`);
      err.code = 'GRAPH';
      throw err;
    }
    return res.text();
  }

  async createDraft({ to, subject, body }) {
    const message = {
      subject,
      body: { contentType: 'HTML', content: body },
      toRecipients: (to || []).map((address) => ({ emailAddress: { address } })),
    };
    const data = await this._fetch(`${this._principal()}/messages`, {
      method: 'POST',
      body: JSON.stringify(message),
    });
    return { draftId: data.id, status: 'created', sent: false };
  }

  async sendDraft({ draftId }) {
    await this._fetch(`${this._principal()}/messages/${encodePathSegment(draftId, 'draftId')}/send`, { method: 'POST' });
    return { draftId, status: 'sent', sent: true };
  }

  async shareFile({ id, recipients }) {
    const data = await this._fetch(`${this._principal()}/drive/items/${encodePathSegment(id)}/invite`, {
      method: 'POST',
      body: JSON.stringify({
        recipients: (recipients || []).map((address) => ({ email: address })),
        roles: ['read'],
        requireSignIn: true,
        sendInvitation: true,
      }),
    });
    return { id, status: 'shared', result: data };
  }

  async deleteFile({ id }) {
    await this._fetch(`${this._principal()}/drive/items/${encodePathSegment(id)}`, { method: 'DELETE' });
    return { id, status: 'deleted' };
  }
}

export function createGraphClient() {
  if (config.dryRun || !hasRealCredentials()) {
    return new DryRunGraphClient();
  }
  return new LiveGraphClient();
}

export { DryRunGraphClient, LiveGraphClient };
