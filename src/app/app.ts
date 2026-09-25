import { Component } from '@angular/core';
import { version } from '../../package.json';
import { DiffView } from './diff-view';
import { FindingsList } from './findings-list';
import { JwtPanel } from './jwt-panel';
import { SAMPLE } from './sample';
import { SourceView } from './source-view';

@Component({
  selector: 'app-root',
  imports: [DiffView, FindingsList, JwtPanel, SourceView],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  protected readonly sample = SAMPLE;
  protected readonly version = version;
  protected readonly removed = SAMPLE.findings.length;
  protected readonly inputMeta = `${SAMPLE.format} · ${new TextEncoder().encode(SAMPLE.input).length} B · ${SAMPLE.input.split('\n').length} ln`;
}
