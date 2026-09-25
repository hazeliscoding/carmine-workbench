import { Rule } from '../../types';
import { START } from '../shared';

interface Format {
  kind: string;
  reason: string;
  pattern: RegExp;
}

// Vendor prefixes and lengths, bounded so a match can't start or end inside a longer word.
const format = (kind: string, reason: string, body: string): Format => ({
  kind,
  reason,
  pattern: new RegExp(`${START}(?:${body})(?![\\w-])`, 'g'),
});

// Stripe pk_ keys are publishable and left alone.
const FORMATS: Format[] = [
  format('aws-access-key-id', 'AWS access key ID', '(?:AKIA|ASIA)[A-Z\\d]{16}'),
  format('github-token', 'GitHub token', 'gh[pousr]_[A-Za-z\\d]{36,255}|github_pat_[A-Za-z\\d_]{80,255}'),
  format('stripe-key', 'Stripe secret key', '(?:(?:sk|rk)_(?:live|test)_|whsec_)[A-Za-z\\d]{16,255}'),
  format('slack-token', 'Slack token', '(?:xox[abposre]|xapp)-[A-Za-z\\d-]{10,255}'),
  format('google-api-key', 'Google API key', 'AIza[\\w-]{35}'),
  format('google-token', 'Google OAuth token', 'ya29\\.[\\w-]{20,}'),
  // The path after the host is the secret; the host stays so a reader knows what it was.
  { kind: 'slack-webhook', reason: 'Slack webhook', pattern: /(?<=hooks\.slack\.com\/services\/)T[A-Z\d]+\/B[A-Z\d]+\/[A-Za-z\d]+/g },
];

export const knownSecretFormats: Rule = {
  name: 'known-secret-formats',
  by: 'format',
  find: (text) =>
    FORMATS.flatMap(({ kind, reason, pattern }) =>
      [...text.matchAll(pattern)].map((m) => ({ start: m.index, end: m.index + m[0].length, kind, reason })),
    ),
};
