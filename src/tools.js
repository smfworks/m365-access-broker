import { config } from './config.js';
import { requireArg, safeId, safeTop, safeQuery, safeEmails } from './validate.js';

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
    const query = safeQuery(args.query);
    const limit = safeTop(args.limit);
    const messages = await graph.searchMail({ query, limit });
    return {
      result: messages,
      resourceType: 'mail',
      resourceRef: `search:${query}`,
      resultSummary: `${messages.length} message(s)`,
    };
  },

  async get_mail(graph, args) {
    requireArg(args, 'id');
    const id = safeId(args.id);
    const message = await graph.getMail({ id });
    return {
      result: message,
      resourceType: 'mail',
      resourceRef: id,
      resultSummary: `message ${id}`,
    };
  },

  async search_files(graph, args) {
    const query = safeQuery(args.query);
    const files = await graph.searchFiles({ query });
    return {
      result: files,
      resourceType: 'file',
      resourceRef: `search:${query}`,
      resultSummary: `${files.length} file(s)`,
    };
  },

  async get_file_text(graph, args) {
    requireArg(args, 'id');
    const id = safeId(args.id);
    const text = await graph.getFileText({ id });
    return {
      result: { id, text },
      resourceType: 'file',
      resourceRef: id,
      resultSummary: `file ${id} text`,
    };
  },

  async create_email_draft(graph, args) {
    requireArg(args, 'to');
    requireArg(args, 'subject');
    requireArg(args, 'body');
    const to = safeEmails(args.to, 'to');
    const draft = await graph.createDraft({ to, subject: args.subject, body: args.body });
    return {
      result: draft,
      resourceType: 'mail',
      resourceRef: draft.draftId,
      resultSummary: `draft ${draft.draftId} created (not sent)`,
    };
  },

  async send_approved_draft(graph, args) {
    requireArg(args, 'draftId');
    const draftId = safeId(args.draftId, 'draftId');
    const sent = await graph.sendDraft({ draftId });
    return {
      result: sent,
      resourceType: 'mail',
      resourceRef: draftId,
      resultSummary: `draft ${draftId} sent`,
    };
  },

  async share_file(graph, args) {
    requireArg(args, 'id');
    requireArg(args, 'recipients');
    const id = safeId(args.id);
    const recipients = safeEmails(args.recipients, 'recipients');
    const shared = await graph.shareFile({ id, recipients });
    return {
      result: shared,
      resourceType: 'file',
      resourceRef: id,
      resultSummary: `file ${id} shared`,
    };
  },

  async delete_file(graph, args) {
    requireArg(args, 'id');
    const id = safeId(args.id);
    const deleted = await graph.deleteFile({ id });
    return {
      result: deleted,
      resourceType: 'file',
      resourceRef: id,
      resultSummary: `file ${id} deleted`,
    };
  },
};
