// Central tool catalog. Each tool declares its Graph scopes and risk class.
// sensitivity: read | write | outbound | destructive
// outbound and destructive always require approval.

export const SENSITIVITY = Object.freeze({
  READ: 'read',
  WRITE: 'write',
  OUTBOUND: 'outbound',
  DESTRUCTIVE: 'destructive',
});

export const TOOL_CATALOG = Object.freeze({
  m365_status: {
    scopes: ['User.Read'],
    sensitivity: SENSITIVITY.READ,
    description: 'Return the signed-in user profile and broker mode.',
  },
  list_today_events: {
    scopes: ['Calendars.Read'],
    sensitivity: SENSITIVITY.READ,
    description: "List today's calendar events.",
  },
  search_mail: {
    scopes: ['Mail.Read'],
    sensitivity: SENSITIVITY.READ,
    returnsExternalContent: true,
    description: 'Search recent mail by keyword.',
  },
  get_mail: {
    scopes: ['Mail.Read'],
    sensitivity: SENSITIVITY.READ,
    returnsExternalContent: true,
    description: 'Read a single message by id.',
  },
  search_files: {
    scopes: ['Files.Read'],
    sensitivity: SENSITIVITY.READ,
    returnsExternalContent: true,
    description: 'Search OneDrive files by name or content.',
  },
  get_file_text: {
    scopes: ['Files.Read'],
    sensitivity: SENSITIVITY.READ,
    returnsExternalContent: true,
    description: 'Download the text content of a file by id.',
  },
  create_email_draft: {
    scopes: ['Mail.ReadWrite'],
    sensitivity: SENSITIVITY.WRITE,
    description: 'Create an Outlook draft. Never sends.',
  },
  send_approved_draft: {
    scopes: ['Mail.Send'],
    sensitivity: SENSITIVITY.OUTBOUND,
    description: 'Send a previously created draft. Requires approval.',
  },
  share_file: {
    scopes: ['Files.ReadWrite'],
    sensitivity: SENSITIVITY.OUTBOUND,
    description: 'Share a OneDrive file with recipients. Requires approval.',
  },
  delete_file: {
    scopes: ['Files.ReadWrite'],
    sensitivity: SENSITIVITY.DESTRUCTIVE,
    description: 'Delete a OneDrive file. Requires approval.',
  },
});

// Tools enabled by default. Anything not in this allowlist is blocked.
export const DEFAULT_ALLOWLIST = Object.freeze([
  'm365_status',
  'list_today_events',
  'search_mail',
  'get_mail',
  'search_files',
  'get_file_text',
  'create_email_draft',
  'send_approved_draft',
  'share_file',
  'delete_file',
]);

export function requiresApprovalByClass(sensitivity) {
  return (
    sensitivity === SENSITIVITY.OUTBOUND ||
    sensitivity === SENSITIVITY.DESTRUCTIVE
  );
}
