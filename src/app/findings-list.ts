import { Component, input } from '@angular/core';
import { Finding } from './sample';

@Component({
  selector: 'app-findings-list',
  template: `
    <h2 class="label head">
      Findings<span class="rule" aria-hidden="true"></span><span class="count">{{ findings().length }}</span>
    </h2>
    <ol>
      @for (f of findings(); track f.label; let i = $index) {
        <li>
          <span class="n mono" aria-hidden="true">{{ (i + 1).toString().padStart(2, '0') }}</span>
          <span class="kind">{{ f.kind }}</span>
          <span class="tag mono">&lt;{{ f.label }}&gt;</span>
          <span class="where">{{ f.where }} · line {{ f.line }}</span>
        </li>
      }
    </ol>
  `,
  styles: `
    :host {
      display: block;
      padding: 10px 0;
    }

    .head {
      display: flex;
      align-items: center;
      gap: var(--space-03);
      height: 32px;
      padding: 0 var(--space-05);
    }

    .rule {
      flex: 1;
      border-top: var(--border-paper);
    }

    li {
      display: grid;
      grid-template-columns: 24px minmax(0, 1fr);
      column-gap: var(--space-03);
      padding: 6px var(--space-05);
      border-left: 2px solid transparent;
    }

    .n {
      grid-row: span 3;
      font-size: var(--text-xs);
      line-height: 18px;
      color: var(--text-meta);
    }

    .kind {
      font-family: var(--font-directive);
      font-size: var(--text-meta-size);
      font-weight: var(--weight-semibold);
      letter-spacing: 0.07em;
      text-transform: uppercase;
      line-height: 18px;
    }

    .tag {
      font-size: var(--text-xs);
      color: var(--text-link);
      overflow-wrap: anywhere;
    }

    .where {
      font-size: var(--text-xs);
      color: var(--text-meta);
    }
  `,
})
export class FindingsList {
  readonly findings = input.required<Finding[]>();
}
