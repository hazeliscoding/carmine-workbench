import { TestBed } from '@angular/core/testing';
import { App } from './app';
import { SAMPLE } from './sample';

describe('App', () => {
  let el: HTMLElement;

  beforeEach(async () => {
    const fixture = TestBed.createComponent(App);
    await fixture.whenStable();
    el = fixture.nativeElement;
  });

  it('renders the Sanitize screen with the sample', () => {
    expect(el.querySelector('h1')?.textContent).toBe('Sanitize');
    expect(el.textContent).toContain('3 secrets removed, review before sharing');
    expect(el.querySelectorAll('app-findings-list li')).toHaveLength(3);
    expect(el.querySelector('app-jwt-panel')?.textContent).toContain('Decoded, not verified');
    expect(el.querySelector('footer')?.textContent).toContain('LOCAL · NO NETWORK');
  });

  it('shows each secret removed and each label added', () => {
    const text = (selector: string) => [...el.querySelectorAll(selector)].map((e) => e.textContent);
    expect(text('del .hit')).toEqual(SAMPLE.findings.map((f) => f.value));
    expect(text('ins .hit')).toEqual(SAMPLE.findings.map((f) => `<${f.label}>`));
  });

  it('keeps secret values out of the sanitized output', () => {
    const output = [...el.querySelectorAll('app-diff-view ins')].map((e) => e.textContent).join('\n');
    for (const f of SAMPLE.findings) expect(output).not.toContain(f.value);
  });

  it('never calls the output clean', () => {
    expect(el.textContent).not.toMatch(/\bclean\b/i);
  });
});
