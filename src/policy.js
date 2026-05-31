import {
  TOOL_CATALOG,
  DEFAULT_ALLOWLIST,
  requiresApprovalByClass,
  isKnownSensitivity,
} from './catalog.js';

// The policy engine decides whether a tool call may proceed and whether it
// needs human approval. It never executes anything itself.
export class PolicyEngine {
  constructor({ allowlist = DEFAULT_ALLOWLIST, catalog = TOOL_CATALOG } = {}) {
    this.allowlist = new Set(allowlist);
    this.catalog = catalog;
  }

  /**
   * Evaluate a tool call.
   * @returns {{allowed:boolean, requiresApproval:boolean, scopes:string[], sensitivity:?string, reasons:string[]}}
   */
  evaluate(toolName, args = {}, ctx = {}) {
    const reasons = [];
    const spec = this.catalog[toolName];

    if (!spec) {
      return {
        allowed: false,
        requiresApproval: false,
        scopes: [],
        sensitivity: null,
        reasons: [`unknown_tool:${toolName}`],
      };
    }

    if (!this.allowlist.has(toolName)) {
      return {
        allowed: false,
        requiresApproval: false,
        scopes: spec.scopes,
        sensitivity: spec.sensitivity,
        reasons: [`tool_not_allowlisted:${toolName}`],
      };
    }

    const needsApproval = requiresApprovalByClass(spec.sensitivity);

    // Fail closed on a catalog entry whose sensitivity is not a recognized
    // class (e.g. a typo) — it is treated as approval-gated above; surface why.
    if (!isKnownSensitivity(spec.sensitivity)) {
      reasons.push(`unknown_sensitivity:${spec.sensitivity}`);
    }

    // Optional least-privilege enforcement: when the caller declares the scopes
    // actually granted to the agent's token, every scope the tool needs must be
    // present or the call is denied. Absent ctx.grantedScopes, the local trusted
    // agent is assumed to hold the catalog scopes (existing behavior).
    if (Array.isArray(ctx.grantedScopes)) {
      const granted = new Set(ctx.grantedScopes);
      const missing = (spec.scopes || []).filter((s) => !granted.has(s));
      if (missing.length) {
        return {
          allowed: false,
          requiresApproval: needsApproval,
          scopes: spec.scopes,
          sensitivity: spec.sensitivity,
          reasons: [...reasons, `missing_scopes:${missing.join(',')}`],
        };
      }
    }

    // Approval-gated tools must carry a granted approval token.
    let approvalSatisfied = true;
    if (needsApproval) {
      approvalSatisfied = ctx.approvalGranted === true;
      if (!approvalSatisfied) {
        reasons.push(`approval_required:${spec.sensitivity}`);
      }
    }

    return {
      allowed: approvalSatisfied,
      requiresApproval: needsApproval,
      scopes: spec.scopes,
      sensitivity: spec.sensitivity,
      reasons,
    };
  }

  listAllowedTools() {
    return [...this.allowlist]
      .filter((name) => this.catalog[name])
      .map((name) => ({
        name,
        sensitivity: this.catalog[name].sensitivity,
        requiresApproval: requiresApprovalByClass(this.catalog[name].sensitivity),
        scopes: this.catalog[name].scopes,
        description: this.catalog[name].description,
      }));
  }
}
