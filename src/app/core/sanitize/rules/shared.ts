// Where a token may start: not inside a word, but right after an escape such as \n in a JSON-escaped log
// line, or after a URL-encoded character such as %3D. Nothing starts right after \ or %, so the n of \n
// or the 3D of %3D is never read as part of a token.
export const START = String.raw`(?:(?<![\w\\%-])|(?<=\\[nrt]|%[\dA-Fa-f]{2}))`;

// Where a bare value ends early: a common HTML tag such as <br>, any closing tag, a label from an earlier
// pass, or a < or > with no more value after it, as in <https://…?token=T>. Other angle brackets can sit
// inside a password, so they don't end it.
export const VALUE_STOP = String.raw`<(?:a|b|i|p|br|hr|td|th|tr|li|ul|ol|em|div|pre|span|code|strong|table|tbody|thead|body|html|head)\b[^<>]*>|<\/[A-Za-z][\w:.-]*>|<[^<>\s]+#\d+>|[<>](?=[\s'"\x60,;&(){}[\]\\<>]|$)`;

// A bare identifier right before ( or [ is code that reads a secret, as in getToken() or os.environ["X"].
// Tokens carry digits, so Bearer T(expired) still counts. Identifiers are mostly lowercase, while a random
// run of letters is about half uppercase.
export function isCallee(value: string): boolean {
  return /^[A-Za-z_$.]+$/.test(value) && value.replace(/[^A-Z]/g, '').length / value.length < 0.4;
}

// X- is a legacy header prefix that says nothing about the value.
export function kindFromName(name: string): string {
  return name
    .replace(/([a-z\d])([A-Z])/g, '$1-$2')
    .toLowerCase()
    .split(/[^a-z\d]+/)
    .filter(Boolean)
    .join('-')
    .replace(/^x-/, '');
}

// For values whose name alone isn't proof, so prose such as "Authorization: denied for usr_034" stays.
export function looksLikeCredential(value: string): boolean {
  return !looksLikeCode(value) && ((value.length >= 8 && /\d/.test(value)) || value.length >= 20);
}

// Code that reads a secret instead of holding one: const token = await getToken(), password: string,
// this.configuration.secret. Real tokens carry digits or dashes in their dotted parts.
export function looksLikeCode(value: string): boolean {
  return (
    /^(?:await|new|typeof|function|async|require|import|return|yield|string|number|boolean|any|unknown|never|void|object|str|int|float|bool|bytes|dict|list)$/i.test(value) ||
    /^[A-Za-z_$]+(?:\.[A-Za-z_$]+)+$/.test(value)
  );
}
