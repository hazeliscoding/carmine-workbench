export interface DecodedJwt {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
}

export interface Finding {
  start: number;
  end: number;
  kind: string;
  reason: string;
  jwt?: DecodedJwt;
}

export interface Rule {
  name: string;
  // Format rules recognise the value itself; context rules recognise where a value sits.
  by: 'format' | 'context';
  find(text: string): Finding[];
}

export interface Change {
  label: string;
  kind: string;
  rule: string;
  reason: string;
  line: number;
  // The replaced span. It can be wider than `value` when an overlapping finding was merged in.
  start: number;
  end: number;
  value: string;
}

export interface LabeledJwt extends DecodedJwt {
  label: string;
}

export interface SanitizeResult {
  output: string;
  changes: Change[];
  jwts: LabeledJwt[];
}
