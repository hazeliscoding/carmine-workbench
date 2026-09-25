import { privateKeys } from './rule';

describe('private-keys rule', () => {
  it('scans many BEGIN lines without an END quickly', () => {
    const armor = ['-----BEGIN', 'PRIVATE KEY-----'].join(' ');
    const started = performance.now();
    privateKeys.find(`${armor}\n`.repeat(35_000));
    expect(performance.now() - started).toBeLessThan(500);
  });
});
