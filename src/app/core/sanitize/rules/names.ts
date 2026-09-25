// A label kind from a header or key name: kebab-case without an X- prefix, so X-Api-Key, apiKey and
// API_KEY all become api-key.
export function kindFromName(name: string): string {
  return name
    .replace(/([a-z\d])([A-Z])/g, '$1-$2')
    .toLowerCase()
    .split(/[^a-z\d]+/)
    .filter(Boolean)
    .join('-')
    .replace(/^x-/, '');
}
