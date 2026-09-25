import { urlParams } from './rule';

describe('url-params rule', () => {
  it('scans 200 KB of dotted text quickly', () => {
    const started = performance.now();
    urlParams.find('a.'.repeat(100_000));
    expect(performance.now() - started).toBeLessThan(500);
  });
});
