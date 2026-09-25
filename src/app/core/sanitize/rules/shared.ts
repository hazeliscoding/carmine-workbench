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
