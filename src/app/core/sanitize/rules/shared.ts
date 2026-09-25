// Where a token may start: not inside a word, but right after an escape such as \n in a JSON-escaped log
// line, or after a URL-encoded character such as %3D. Nothing starts right after \ or %, so the n of \n
// or the 3D of %3D is never read as part of a token.
export const START = String.raw`(?:(?<![\w\\%-])|(?<=\\[nrt]|%[\dA-Fa-f]{2}))`;

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
  return (value.length >= 8 && /\d/.test(value)) || value.length >= 20;
}
