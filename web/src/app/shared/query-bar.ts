import {
  Component,
  computed,
  DestroyRef,
  ElementRef,
  effect,
  inject,
  input,
  model,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import {
  acceptCompletion,
  autocompletion,
  closeBrackets,
  completionStatus,
  startCompletion,
  type Completion,
  type CompletionContext,
} from '@codemirror/autocomplete';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { HighlightStyle, StreamLanguage, syntaxHighlighting } from '@codemirror/language';
import { linter, type Diagnostic } from '@codemirror/lint';
import { EditorState, Prec } from '@codemirror/state';
import { EditorView, keymap, placeholder as cmPlaceholder } from '@codemirror/view';
import { tags } from '@lezer/highlight';
import { Api, errorMessage, QueryIssue, SavedQuery } from '../core/api';
import { Auth } from '../core/auth';

/** Colours only: fields, keywords, operators, strings. Parsing is the appliance's. */
const queryLanguage = StreamLanguage.define<null>({
  token(stream) {
    if (stream.eatSpace()) return null;
    if (stream.match(/^"(?:[^"\\]|\\.)*"?/)) return 'string';
    if (stream.match(/^(AND|OR|NOT|TO)(?![^\s()[\]"!<>&|{}])/i)) return 'keyword';
    if (stream.match(/^(&&|\|\||[!<>]=?)/)) return 'operator';
    if (stream.match(/^[()[\]]/)) return 'bracket';
    if (stream.match(/^[A-Za-z_][\w.]*:(?![0-9a-fA-F]{0,4}:)/)) return 'propertyName';
    if (stream.match(/^\*/)) return 'atom';
    stream.match(/^[^\s()[\]"!<>&|{}]+/) || stream.next();
    return 'content';
  },
});

const highlight = HighlightStyle.define([
  { tag: tags.propertyName, color: 'var(--cds-alias-status-info, #0072a3)' },
  { tag: tags.keyword, color: 'var(--cds-global-color-violet-600, #8939ad)', fontWeight: '600' },
  { tag: tags.operator, color: 'var(--cds-global-color-violet-600, #8939ad)' },
  { tag: tags.string, color: 'var(--cds-alias-status-success, #3c8500)' },
  { tag: tags.atom, color: 'var(--cds-alias-status-warning-shade, #c25400)' },
]);

const theme = EditorView.theme({
  '&': {
    fontSize: '13px',
    flex: '1',
    minWidth: '0',
    background: 'transparent',
    color: 'var(--cds-alias-typography-color-400)',
  },
  '&.cm-focused': { outline: 'none' },
  '.cm-scroller': {
    fontFamily: 'var(--cds-global-typography-monospace-font-family, monospace)',
    overflow: 'hidden',
    lineHeight: '24px',
  },
  '.cm-content': { padding: '2px 0', caretColor: 'var(--cds-alias-typography-color-400)' },
  '.cm-line': { padding: '0 4px' },
  '.cm-placeholder': { color: 'var(--cds-alias-typography-color-200)' },
  '.cm-tooltip': {
    background: 'var(--cds-alias-object-overlay-background, #fff)',
    color: 'var(--cds-alias-typography-color-400)',
    border: '1px solid var(--cds-alias-object-border-color, #ccc)',
    borderRadius: '3px',
  },
  '.cm-tooltip.cm-tooltip-autocomplete > ul': {
    fontFamily: 'var(--cds-global-typography-monospace-font-family, monospace)',
    maxHeight: '18em',
  },
  '.cm-tooltip-autocomplete ul li[aria-selected]': {
    background: 'var(--cds-alias-status-info, #0072a3)',
    color: '#fff',
  },
  '.cm-completionDetail': {
    fontStyle: 'normal',
    opacity: '0.7',
    marginLeft: '1em',
    fontFamily: 'var(--cds-global-typography-font-family, sans-serif)',
  },
  '.cm-diagnostic': { fontFamily: 'var(--cds-global-typography-font-family, sans-serif)' },
});

const HISTORY_SIZE = 20;

/**
 * A one-line query editor (docs/QUERIES.md): highlighting, completions and
 * checking as you type, from the appliance. Enter runs the query; ↑ in an
 * empty bar recalls recent ones.
 */
@Component({
  selector: 'nfa-query-bar',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="bar" [class.invalid]="!!error()" [class.dirty]="dirty()">
      <cds-icon shape="search" class="icon"></cds-icon>
      <div class="editor" #host></div>
      @if (text()) {
        <button
          type="button"
          class="btn btn-sm btn-link btn-icon clear"
          (click)="clear()"
          aria-label="Clear the query"
          i18n-aria-label="@@queryBar.clear"
        >
          <cds-icon shape="times"></cds-icon>
        </button>
      }
      <button
        type="button"
        class="btn btn-sm btn-link btn-icon"
        [class.active]="savedOpen()"
        (click)="toggleSaved()"
        aria-label="Saved queries"
        i18n-aria-label="@@queryBar.saved"
      >
        <cds-icon shape="bookmark"></cds-icon>
      </button>
      <button
        type="button"
        class="btn btn-sm btn-link btn-icon"
        (click)="helpOpen.set(!helpOpen()); savedOpen.set(false)"
        aria-label="Query syntax"
        i18n-aria-label="@@queryBar.help"
      >
        <cds-icon shape="info-circle"></cds-icon>
      </button>
      @if (!live()) {
        <button
          type="button"
          class="btn btn-sm btn-primary run"
          (click)="run()"
          [disabled]="running()"
          i18n="@@queryBar.run"
        >
          Run
        </button>
      }
    </div>
    @if (error(); as e) {
      <div class="issue error" role="alert">
        {{ e.message }}
        @if (e.hint) {
          &nbsp;· {{ e.hint }}
        }
      </div>
    } @else {
      @for (w of warnings(); track $index) {
        <div class="issue warn">
          <cds-icon shape="exclamation-triangle" status="warning" size="14"></cds-icon>
          {{ w.message }}
          @if (w.hint) {
            &nbsp;· {{ w.hint }}
          }
          <span class="muted nothing" i18n="@@queryBar.matchesNothing">(matches nothing)</span>
        </div>
      }
    }
    @if (savedOpen()) {
      <div class="saved card">
        <div class="card-block">
          @if (!live()) {
            <form class="save-form" (ngSubmit)="saveCurrent()">
              <input
                class="clr-input"
                name="savedName"
                [(ngModel)]="saveName"
                placeholder="Name this query"
                i18n-placeholder="@@queryBar.saveName"
                aria-label="Name"
                i18n-aria-label="@@queryBar.name"
              />
              <label class="share"
                ><input type="checkbox" name="saveShared" [(ngModel)]="saveShared" />
                <ng-container i18n="@@queryBar.share">Share with everyone</ng-container></label
              >
              <button
                type="submit"
                class="btn btn-sm btn-primary"
                [disabled]="!text().trim() || !saveName.trim()"
                i18n="@@queryBar.save"
              >
                Save
              </button>
            </form>
          }
          @if (savedError()) {
            <div class="issue error">{{ savedError() }}</div>
          }
          <table class="table table-compact table-noborder">
            <tbody>
              @for (q of saved(); track q.id) {
                <tr>
                  <td class="left name">
                    <a href="#" (click)="$event.preventDefault(); use(q.query)">{{ q.name }}</a>
                    @if (q.owner !== me()) {
                      <div class="muted small">{{ q.owner }}</div>
                    }
                  </td>
                  <td class="left">
                    <code>{{ q.query }}</code>
                  </td>
                  <td class="right actions">
                    @if (q.owner === me() || auth.isAdmin()) {
                      <label class="share small" [title]="shareTitle"
                        ><input type="checkbox" [checked]="q.shared" (change)="toggleShared(q)" />
                        <ng-container i18n="@@queryBar.shared">shared</ng-container></label
                      >
                      <button
                        type="button"
                        class="btn btn-sm btn-link btn-icon"
                        (click)="remove(q)"
                        aria-label="Delete"
                        i18n-aria-label="@@common.delete"
                      >
                        <cds-icon shape="trash"></cds-icon>
                      </button>
                    } @else if (q.shared) {
                      <span class="label" i18n="@@queryBar.sharedLabel">shared</span>
                    }
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td class="left muted" i18n="@@queryBar.noneSaved">
                    No saved queries yet. Save the one in the bar to come back to it.
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </div>
    }
    @if (helpOpen()) {
      <div class="help card">
        <div class="card-block">
          <table class="table table-compact table-noborder">
            <tbody>
              <tr>
                <td class="left"><code>dst_port:443</code></td>
                <td class="left" i18n="@@queryBar.helpField">a field and a value</td>
              </tr>
              <tr>
                <td class="left"><code>country:(US OR CA)</code></td>
                <td class="left" i18n="@@queryBar.helpList">any of several values</td>
              </tr>
              <tr>
                <td class="left"><code>dst_port:[1 TO 1023]</code></td>
                <td class="left" i18n="@@queryBar.helpRange">a range (also 1-1023)</td>
              </tr>
              <tr>
                <td class="left"><code>bytes:&gt;100MB</code></td>
                <td class="left" i18n="@@queryBar.helpCompare">
                  a comparison: &gt; &gt;= &lt; &lt;=
                </td>
              </tr>
              <tr>
                <td class="left"><code>threat:*</code></td>
                <td class="left" i18n="@@queryBar.helpAny">any value</td>
              </tr>
              <tr>
                <td class="left"><code>a AND b</code>, <code>a OR b</code>, <code>a b</code></td>
                <td class="left" i18n="@@queryBar.helpBool">
                  both; either; either (terms side by side are OR)
                </td>
              </tr>
              <tr>
                <td class="left"><code>NOT a</code>, <code>(a OR b) AND c</code></td>
                <td class="left" i18n="@@queryBar.helpNot">
                  not; grouping (AND binds tighter than OR)
                </td>
              </tr>
              <tr>
                <td class="left"><code>nas</code>, <code>10.0.0.0/8</code></td>
                <td class="left" i18n="@@queryBar.helpBare">
                  an address or name alone means host:
                </td>
              </tr>
              <tr>
                <td class="left"><code>device:"Living room TV"</code></td>
                <td class="left" i18n="@@queryBar.helpQuote">quotes for values with spaces</td>
              </tr>
            </tbody>
          </table>
          <p class="muted" i18n="@@queryBar.helpKeys">
            Tab or Enter picks a suggestion; Ctrl+Space shows them; ↑ in an empty bar recalls recent
            queries.
          </p>
        </div>
      </div>
    }
  `,
  styles: `
    .bar {
      display: flex;
      align-items: center;
      gap: 4px;
      padding: 0 0 0 4px;
      border-bottom: 1px solid var(--cds-alias-object-interaction-border-color, #8c8c8c);
    }
    .bar:focus-within {
      border-bottom-color: var(--cds-alias-object-interaction-border-color-active, #0072a3);
      box-shadow: 0 1px 0 var(--cds-alias-object-interaction-border-color-active, #0072a3);
    }
    .bar.invalid {
      border-bottom-color: var(--cds-alias-status-danger);
    }
    .icon {
      color: var(--cds-alias-typography-color-300);
      flex: none;
    }
    .editor {
      flex: 1;
      min-width: 0;
    }
    .btn {
      margin: 0;
    }
    .run {
      margin-left: 4px;
    }
    .issue {
      font-size: 12px;
      margin: 4px 0 0 24px;
    }
    .issue.error {
      color: var(--cds-alias-status-danger);
    }
    .muted {
      color: var(--cds-alias-typography-color-300);
    }
    .nothing {
      margin-left: 4px;
    }
    .btn.active {
      color: var(--cds-alias-status-info, #0072a3);
    }
    .saved {
      margin: 8px 0 0;
      max-width: 60rem;
    }
    .saved .table {
      margin: 6px 0 0;
    }
    .saved code {
      word-break: break-word;
    }
    .saved .name {
      white-space: nowrap;
    }
    .saved .actions {
      white-space: nowrap;
      text-align: right;
    }
    .save-form {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }
    .save-form .clr-input {
      width: 16rem;
    }
    .share {
      display: inline-flex;
      gap: 4px;
      align-items: center;
      font-size: 12px;
    }
    .small {
      font-size: 11px;
    }
    .help {
      margin: 8px 0 0;
      max-width: 46rem;
    }
    .help .table {
      margin: 0;
    }
    .help code {
      white-space: nowrap;
    }
    .help p {
      font-size: 12px;
      margin-top: 6px;
    }
  `,
})
export class QueryBar {
  /** The query in effect; set when one runs. */
  readonly query = model<string>('');
  readonly placeholder = input(
    $localize`:@@queryBar.placeholder:Query, e.g. host:nas AND NOT country:(US OR CA)`,
  );
  /** In a form: the query follows the text as it is typed, with no Run button. */
  readonly live = input(false);

  private api = inject(Api);
  readonly auth = inject(Auth);
  private host = viewChild.required<ElementRef<HTMLElement>>('host');
  private view?: EditorView;

  readonly text = signal('');
  readonly error = signal<QueryIssue | null>(null);
  readonly warnings = signal<QueryIssue[]>([]);
  readonly running = signal(false);
  readonly helpOpen = signal(false);
  readonly savedOpen = signal(false);
  readonly saved = signal<SavedQuery[]>([]);
  readonly savedError = signal('');
  readonly me = computed(() => this.auth.user()?.username ?? '');
  readonly shareTitle = $localize`:@@queryBar.shareTitle:Shared queries are listed for everyone; only you or an administrator can change them.`;
  saveName = '';
  saveShared = false;
  readonly dirty = signal(false);

  constructor() {
    effect(() => {
      const q = this.query();
      const v = this.view;
      // Set from outside (a drill-down, a link): show it, with its warnings.
      if (v && v.state.doc.toString() !== q) {
        v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: q } });
        untracked(() => this.check(q));
      }
      this.dirty.set(untracked(this.text) !== q);
    });
    effect(() => {
      const el = this.host().nativeElement;
      if (this.view) return;
      untracked(() => {
        this.view = new EditorView({ parent: el, state: this.createState(this.query()) });
        this.text.set(this.query());
        if (this.query()) this.check(this.query());
      });
    });
    inject(DestroyRef).onDestroy(() => this.view?.destroy());
  }

  private createState(doc: string) {
    return EditorState.create({
      doc,
      extensions: [
        // One line: newlines (from a paste) become spaces.
        EditorState.transactionFilter.of((tr) =>
          tr.newDoc.lines > 1
            ? [
                tr,
                {
                  changes: {
                    from: 0,
                    to: tr.newDoc.length,
                    insert: tr.newDoc.toString().replace(/\s*\n\s*/g, ' '),
                  },
                  sequential: true,
                },
              ]
            : tr,
        ),
        history(),
        closeBrackets(),
        queryLanguage,
        syntaxHighlighting(highlight),
        theme,
        cmPlaceholder(this.placeholder()),
        autocompletion({
          override: [(ctx) => this.complete(ctx)],
          icons: false,
          activateOnTypingDelay: 150,
        }),
        linter((v) => this.lint(v), { delay: 400 }),
        Prec.high(
          keymap.of([
            {
              key: 'Enter',
              run: (v) =>
                completionStatus(v.state) === 'active' ? false : (this.live() || this.run(), true),
            },
            { key: 'ArrowUp', run: (v) => (v.state.doc.length === 0 ? startCompletion(v) : false) },
            { key: 'Tab', run: acceptCompletion },
          ]),
        ),
        keymap.of([...defaultKeymap, ...historyKeymap]),
        EditorView.updateListener.of((u) => {
          if (!u.docChanged) return;
          const t = u.state.doc.toString();
          this.text.set(t);
          this.error.set(null);
          if (this.live()) this.query.set(t.trim());
          this.dirty.set(t !== this.query());
        }),
        EditorView.contentAttributes.of({
          'aria-label': $localize`:@@queryBar.query:Query`,
          spellcheck: 'false',
        }),
      ],
    });
  }

  /** Suggestions from the appliance; recent queries in an empty bar. */
  private async complete(ctx: CompletionContext) {
    const doc = ctx.state.doc.toString();
    if (!doc) {
      if (!ctx.explicit) return null;
      await this.loadSaved();
      const options: Completion[] = [
        ...this.saved().map((q): Completion => ({
          label: q.name,
          apply: q.query,
          detail: q.query,
          type: 'saved',
          boost: 1,
        })),
        ...this.recent().map((q): Completion => ({ label: q, type: 'text' })),
      ];
      return options.length ? { from: 0, options, filter: false } : null;
    }
    if (!ctx.explicit && !ctx.matchBefore(/[^\s()[\]!<>&|{}]+$|[:(]\s*$/)) return null;
    let r;
    try {
      r = await this.api.suggestQuery(doc, ctx.pos);
    } catch {
      return null;
    }
    if (ctx.aborted || !r.options.length) return null;
    return {
      from: r.from,
      to: r.to,
      filter: false,
      options: r.options.map((o): Completion => ({
        label: o.label,
        apply: o.apply,
        detail: o.detail,
        type: o.kind === 'field' ? 'property' : o.kind === 'keyword' ? 'keyword' : 'constant',
        boost: o.kind === 'keyword' ? -1 : 0,
      })),
    };
  }

  private async lint(v: EditorView): Promise<Diagnostic[]> {
    const doc = v.state.doc.toString();
    if (!doc.trim()) {
      this.warnings.set([]);
      return [];
    }
    const r = await this.api.checkQuery(doc);
    if (v.state.doc.toString() !== doc) return [];
    const span = (i: QueryIssue) => {
      const from = Math.min(i.pos, doc.length);
      return { from, to: Math.min(doc.length, Math.max(from + i.len, from + 1)) };
    };
    const msg = (i: QueryIssue) => i.message + (i.hint ? ' · ' + i.hint : '');
    if (r.error) return [{ ...span(r.error), severity: 'error', message: msg(r.error) }];
    return r.warnings.map((w) => ({ ...span(w), severity: 'warning', message: msg(w) }));
  }

  private async check(q: string) {
    if (!q) {
      this.error.set(null);
      this.warnings.set([]);
      return;
    }
    const r = await this.api.checkQuery(q);
    this.error.set(r.error ?? null);
    this.warnings.set(r.warnings);
  }

  /** Runs the query: checked, then set in canonical form. */
  async run() {
    const v = this.view;
    if (!v) return;
    const text = v.state.doc.toString().trim();
    if (!text) {
      this.clear();
      return;
    }
    this.running.set(true);
    const r = await this.api.checkQuery(text);
    this.running.set(false);
    if (r.error) {
      this.error.set(r.error);
      v.dispatch({ selection: { anchor: Math.min(r.error.pos, v.state.doc.length) } });
      v.focus();
      return;
    }
    const q = r.query ?? text;
    this.error.set(null);
    this.warnings.set(r.warnings);
    this.remember(q);
    if (v.state.doc.toString() !== q)
      v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: q } });
    this.query.set(q);
    this.dirty.set(false);
  }

  async loadSaved() {
    try {
      this.saved.set(await this.api.savedQueries());
    } catch {
      /* keep what we have */
    }
  }

  toggleSaved() {
    this.savedOpen.set(!this.savedOpen());
    this.helpOpen.set(false);
    this.savedError.set('');
    if (this.savedOpen()) this.loadSaved();
  }

  /** Puts a saved query in the bar and runs it. */
  use(q: string) {
    this.view?.dispatch({ changes: { from: 0, to: this.view.state.doc.length, insert: q } });
    this.savedOpen.set(false);
    if (this.live()) this.query.set(q);
    else this.run();
  }

  async saveCurrent() {
    this.savedError.set('');
    try {
      const mine = this.saved().find(
        (q) => q.owner === this.me() && q.name === this.saveName.trim(),
      );
      await this.api.saveQuery({
        id: mine?.id,
        name: this.saveName.trim(),
        query: this.text().trim(),
        shared: this.saveShared,
      });
      this.saveName = '';
      this.saveShared = false;
      await this.loadSaved();
    } catch (err) {
      this.savedError.set(errorMessage(err));
    }
  }

  async toggleShared(q: SavedQuery) {
    try {
      await this.api.saveQuery({ ...q, shared: !q.shared });
    } catch (err) {
      this.savedError.set(errorMessage(err));
    }
    await this.loadSaved();
  }

  async remove(q: SavedQuery) {
    try {
      await this.api.deleteQuery(q.id);
    } catch (err) {
      this.savedError.set(errorMessage(err));
    }
    await this.loadSaved();
  }

  clear() {
    this.view?.dispatch({ changes: { from: 0, to: this.view.state.doc.length, insert: '' } });
    this.error.set(null);
    this.warnings.set([]);
    this.query.set('');
    this.view?.focus();
  }

  private get storageKey() {
    return 'tributary.queries.' + (this.auth.user()?.username ?? '');
  }

  private recent(): string[] {
    try {
      const v = JSON.parse(localStorage.getItem(this.storageKey) ?? '[]');
      return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
    } catch {
      return [];
    }
  }

  private remember(q: string) {
    try {
      const list = [q, ...this.recent().filter((x) => x !== q)].slice(0, HISTORY_SIZE);
      localStorage.setItem(this.storageKey, JSON.stringify(list));
    } catch {
      /* storage unavailable: no history */
    }
  }
}
