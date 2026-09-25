import { Rule } from '../../types';

interface Format {
  kind: string;
  reason: string;
  pattern: RegExp;
}

// Vendor prefixes and lengths. Each pattern is bounded so it can't start or end inside a longer word.
// Stripe pk_ keys are publishable and left alone.
const FORMATS: Format[] = [
  { kind: 'aws-access-key-id', reason: 'AWS access key ID', pattern: /(?<![A-Z\d])(?:AKIA|ASIA)[A-Z\d]{16}(?![A-Z\d])/g },
  { kind: 'github-token', reason: 'GitHub token', pattern: /(?<![\w-])(?:gh[pousr]_[A-Za-z\d]{36,255}|github_pat_[A-Za-z\d_]{80,255})(?![\w-])/g },
  { kind: 'stripe-key', reason: 'Stripe secret key', pattern: /(?<![\w-])(?:(?:sk|rk)_(?:live|test)_|whsec_)[A-Za-z\d]{16,255}(?![\w-])/g },
  { kind: 'slack-token', reason: 'Slack token', pattern: /(?<![\w-])(?:xox[abposr]|xapp)-[A-Za-z\d-]{10,255}(?![\w-])/g },
  // The path after the host is the secret; the host stays so a reader knows what it was.
  { kind: 'slack-webhook', reason: 'Slack webhook', pattern: /(?<=hooks\.slack\.com\/services\/)T[A-Z\d]+\/B[A-Z\d]+\/[A-Za-z\d]+/g },
  { kind: 'google-api-key', reason: 'Google API key', pattern: /(?<![\w-])AIza[\w-]{35}(?![\w-])/g },
  { kind: 'google-token', reason: 'Google OAuth token', pattern: /(?<![\w-])ya29\.[\w-]{20,}/g },
];

export const knownSecretFormats: Rule = {
  name: 'known-secret-formats',
  by: 'format',
  find: (text) =>
    FORMATS.flatMap(({ kind, reason, pattern }) =>
      [...text.matchAll(pattern)].map((m) => ({ start: m.index, end: m.index + m[0].length, kind, reason })),
    ),
};
