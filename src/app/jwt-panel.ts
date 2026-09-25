import { Component, input } from '@angular/core';
import { JwtExplain } from './sample';

@Component({
  selector: 'app-jwt-panel',
  template: `
    <section aria-labelledby="jwt-title">
      <div class="head">
        <h2 class="label" id="jwt-title">JWT</h2>
        <span class="tag mono">&lt;{{ jwt().label }}&gt;</span>
        <span class="meta mono">{{ jwt().alg }} · signature removed</span>
        <span class="spacer"></span>
        @if (jwt().expired) {
          <span class="badge expired">Expired</span>
        }
      </div>
      @for (group of groups; track group.name) {
        <h3 class="label group">{{ group.name }}</h3>
        <dl class="mono">
          @for (f of jwt()[group.key]; track f.key) {
            <div>
              <dt>{{ f.key }}</dt>
              <dd [class]="f.type">{{ f.value }}</dd>
              <dd class="note" [class.alert]="f.alert">{{ f.note }}</dd>
            </div>
          }
        </dl>
      }
      <p class="footnote">Decoded, not verified. The signature was removed and never checked.</p>
    </section>
  `,
  styles: `
    :host {
      display: block;
      border-top: var(--border-paper);
    }

    .head {
      display: flex;
      align-items: center;
      gap: var(--space-03);
      height: 32px;
      padding: 0 var(--space-05);
      border-bottom: var(--border-paper);
    }

    .tag {
      font-size: var(--text-xs);
      color: var(--text-link);
    }

    .meta {
      font-size: var(--text-xs);
      color: var(--text-meta);
    }

    .spacer {
      flex: 1;
    }

    .expired {
      color: var(--directive-red);
    }

    .group {
      padding: var(--space-03) var(--space-05) var(--space-01);
    }

    dl {
      font-size: 12.5px;
      line-height: 1.5;
    }

    dl div {
      display: grid;
      grid-template-columns: 72px minmax(0, 1fr) auto;
      gap: var(--space-04);
      padding: 4px var(--space-05);
      border-bottom: var(--border-paper);
    }

    dd {
      overflow-wrap: anywhere;
    }

    .string {
      color: var(--amber);
    }

    .number {
      color: var(--text-link);
    }

    .note {
      font-family: var(--font-official);
      font-size: var(--text-meta-size);
      text-align: right;
      color: var(--text-meta);
    }

    .note.alert {
      color: var(--directive-red);
    }

    .footnote {
      padding: var(--space-04) var(--space-05);
      max-width: 560px;
      font-size: var(--text-meta-size);
      color: var(--text-secondary);
    }
  `,
})
export class JwtPanel {
  readonly jwt = input.required<JwtExplain>();

  protected readonly groups = [
    { name: 'Header', key: 'header' },
    { name: 'Claims', key: 'claims' },
  ] as const;
}
