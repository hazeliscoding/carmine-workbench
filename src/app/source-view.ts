import { Component, computed, input } from '@angular/core';
import { Finding } from './sample';
import { segments } from './text';

@Component({
  selector: 'app-source-view',
  template: `
    <ol class="mono">
      @for (line of lines(); track $index) {
        <li>
          <span class="n" aria-hidden="true">{{ $index + 1 }}</span>
          <pre>@for (s of line; track $index) {@if (s.hit) {<mark>{{ s.text }}</mark>} @else {<span>{{ s.text }}</span>}}</pre>
        </li>
      }
    </ol>
  `,
  styles: `
    ol {
      padding: var(--space-04) 0;
      font-size: 12.5px;
      line-height: var(--leading-code);
    }

    li {
      display: grid;
      grid-template-columns: 40px minmax(0, 1fr);
    }

    .n {
      padding-right: 10px;
      text-align: right;
      color: var(--text-meta);
      user-select: none;
    }

    pre {
      padding: 0 var(--space-05) 0 var(--space-03);
      font: inherit;
      color: var(--text-secondary);
      white-space: pre-wrap;
      word-break: break-all;
    }

    mark {
      background: var(--mark-bg);
      color: var(--text-primary);
      box-shadow: inset 0 -1px var(--directive-red);
    }
  `,
})
export class SourceView {
  readonly text = input.required<string>();
  readonly secrets = input.required<Finding[]>();

  protected readonly lines = computed(() => {
    const values = this.secrets().map((f) => f.value);
    return this.text()
      .split('\n')
      .map((line) => segments(line, values));
  });
}
