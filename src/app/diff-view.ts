import { Component, computed, input } from '@angular/core';
import { Finding } from './sample';
import { diffLines, segments } from './text';

@Component({
  selector: 'app-diff-view',
  template: `
    <ol class="mono">
      @for (line of lines(); track $index) {
        <li [class]="line.op">
          <span class="n" aria-hidden="true">{{ line.a }}</span>
          <span class="n" aria-hidden="true">{{ line.b }}</span>
          <span class="sign" aria-hidden="true">{{ signs[line.op] }}</span>
          @switch (line.op) {
            @case ('del') {
              <del><span class="visually-hidden">Removed: </span>@for (s of line.parts; track $index) {<span [class.hit]="s.hit">{{ s.text }}</span>}</del>
            }
            @case ('add') {
              <ins><span class="visually-hidden">Added: </span>@for (s of line.parts; track $index) {<span [class.hit]="s.hit">{{ s.text }}</span>}</ins>
            }
            @default {
              <span class="text">{{ line.text }}</span>
            }
          }
        </li>
      }
    </ol>
  `,
  styles: `
    ol {
      padding: 6px 0;
      font-size: 12.5px;
      line-height: var(--leading-code);
    }

    li {
      display: grid;
      grid-template-columns: 36px 36px 16px minmax(0, 1fr);
    }

    .n {
      padding-right: var(--space-03);
      text-align: right;
      color: var(--text-meta);
      user-select: none;
    }

    .sign {
      user-select: none;
    }

    .text,
    del,
    ins {
      padding-right: var(--space-05);
      white-space: pre-wrap;
      word-break: break-all;
      text-decoration: none;
    }

    .text {
      color: var(--text-secondary);
    }

    .del .sign,
    del {
      background: var(--diff-del-bg);
      color: var(--text-primary);
    }

    .add .sign,
    ins {
      background: var(--diff-add-bg);
      color: var(--text-primary);
    }

    del .hit {
      text-decoration: line-through;
    }

    ins .hit {
      color: var(--text-link);
      font-weight: var(--weight-semibold);
    }
  `,
})
export class DiffView {
  readonly before = input.required<string>();
  readonly after = input.required<string>();
  readonly findings = input.required<Finding[]>();

  protected readonly signs = { same: '', del: '−', add: '+' };

  protected readonly lines = computed(() => {
    const values = this.findings().map((f) => f.value);
    const labels = this.findings().map((f) => `<${f.label}>`);
    return diffLines(this.before(), this.after()).map((line) => ({
      ...line,
      parts: segments(line.text, line.op === 'del' ? values : labels),
    }));
  });
}
