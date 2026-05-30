import { config } from './config.js';

// Tool handlers. Each receives the graph client and validated args and returns
// { result, resourceType, resourceRef, resultSummary } for the audit log.

export const TOOL_HANDLERS = {
  async m365_status(graph) {
    const me = await graph.me();
    return {
      result: { user: me, mode: graph.mode, dryRun: config.dryRun },
      resourceType: 'user',
      resourceRef: me.id,
      resultSummary: `status for ${me.userPrincipalName} (${graph.mode})`,
    };
  },

  async list_today_events(graph) {
    const events = await graph.listTodayEvents();
    return {
      result: events,
      resourceType: 'calendar',
      resourceRef: 'today',
      resultSummary: `${events.length} event(s)`,
    };
  },

  async search_mail(graph, args) {
    const messages = await graph.searchMail({ query: args.query, limit: args.limit });
    return {
      result: messages,
      resourceType: 'mail',
      resourceRef: `search:${args.query || ''}`,
      resultSummary: `${messages.length} message(s)`,
    };
  },

  async get_mail(graph, args) {
    requireArg(args, 'id');
    const message = await graph.getMail({ id: args.id });
    return {
      result: message,
      resourceType: 'mail',
      resourceRef: args.id,
      resultSummary: `message ${args.id}`,
    };
  },

  async search_files(graph, args) {
    const files = await graph.searchFiles({ query: args.query });
    return {
      result: files,
      resourceType: 'file',
      resourceRef: `search:${args.query || ''}`,
      resultSummary: `${files.length} file(s)`,
    };
  },

  async get_file_text(graph, args) {
    requireArg(args, 'id');
    const text = await graph.getFileText({ id: args.id });
    return {
      result: { id: args.id, text },
      resourceType: 'file',
      resourceRef: args.id,
      resultSummary: `file ${args.id} text`,
    };
  },

  async create_email_draft(graph, args) {
    requireArg(args, 'to');
    requireArg(args, 'subject');
    requireArg(args, 'body');
    const draft = await graph.createDraft({ to: args.to, subject: args.subject, body: args.body });
    return {
      result: draft,
      resourceType: 'mail',
      resourceRef: draft.draftId,
      resultSummary: `draft ${draft.draftId} created (not sent)`,
    };
  },

  async send_approved_draft(graph, args) {
    requireArg(args, 'draftId');
    const sent = await graph.sendDraft({ draftId: args.draftId });
    return {
      result: sent,
      resourceType: 'mail',
      resourceRef: args.draftId,
      resultSummary: `draft ${args.draftId} sent`,
    };
  },

  async share_file(graph, args) {
    requireArg(args, 'id');
    requireArg(args, 'recipients');
    const shared = await graph.shareFile({ id: args.id, recipients: args.recipients });
    return {
      result: shared,
      resourceType: 'file',
      resourceRef: args.id,
      resultSummary: `file ${args.id} shared`,
    };
  },

  async delete_file(graph, args) {
    requireArg(args, 'id');
    const deleted = await graph.deleteFile({ id: args.id });
    return {
      result: deleted,
      resourceType: 'file',
      resourceRef: args.id,
      resultSummary: `file ${args.id} deleted`,
    };
  },
};

function requireArg(args, name) {
  if (args[name] === undefined || args[name] === null || args[name] === '') {
    const err = new Error(`missing_required_arg:${name}`);
    err.code = 'BAD_ARGS';
    throw err;
  }
}
