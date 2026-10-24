import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { AIQueryResult, AISettings, Api, errorMessage } from '../core/api';
import { ModelPicker } from '../shared/model-picker';

const ANTHROPIC_URL = 'https://api.anthropic.com';
/** Preselected for Anthropic when the endpoint offers it. */
const ANTHROPIC_DEFAULT_MODEL = 'claude-opus-5-5';

/** The AI query assistant (Configuration → AI Assistant). */
@Component({
  selector: 'nfa-ai-settings',
  imports: [ClarityModule, FormsModule, ModelPicker],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.ai">AI Assistant</h2>
        <p class="subtitle" i18n="@@ai.subtitle">
          A language model that writes queries from plain English. It only writes them: the
          appliance checks each one, and nothing runs until you press Run.
        </p>
      </div>
    </div>

    @if (saved()) {
      <div class="alert alert-success" role="alert">
        <div class="alert-items">
          <div class="alert-item static">
            <span class="alert-text" i18n="@@ai.saved">Saved.</span>
          </div>
        </div>
      </div>
    }
    @if (error()) {
      <div class="alert alert-danger" role="alert">
        <div class="alert-items">
          <div class="alert-item static">
            <span class="alert-text">{{ error() }}</span>
          </div>
        </div>
      </div>
    }

    @if (c(); as c) {
      <form clrForm clrLayout="horizontal" clrLabelSize="3" (ngSubmit)="save()" class="ai-form">
        <div class="card">
          <div class="card-header" i18n="@@ai.model">Model</div>
          <div class="card-block">
            <clr-toggle-container>
              <label i18n="@@ai.assistant">Assistant</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="enabled" [(ngModel)]="c.enabled" />
                <label i18n="@@ai.enable">Show the AI button in query bars</label>
              </clr-toggle-wrapper>
            </clr-toggle-container>
            <clr-radio-container clrInline>
              <label i18n="@@ai.provider">API</label>
              <clr-radio-wrapper>
                <input
                  type="radio"
                  clrRadio
                  name="provider"
                  value="anthropic"
                  [ngModel]="c.provider"
                  (ngModelChange)="setProvider($event)"
                />
                <label>Anthropic</label>
              </clr-radio-wrapper>
              <clr-radio-wrapper>
                <input
                  type="radio"
                  clrRadio
                  name="provider"
                  value="openai"
                  [ngModel]="c.provider"
                  (ngModelChange)="setProvider($event)"
                />
                <label i18n="@@ai.openai">OpenAI-compatible</label>
              </clr-radio-wrapper>
              <clr-control-helper>
                @if (c.provider === 'anthropic') {
                  <ng-container i18n="@@ai.anthropicHelp"
                    >Claude's Messages API, or a gateway's Anthropic endpoint.</ng-container
                  >
                } @else {
                  <ng-container i18n="@@ai.openaiHelp"
                    >OpenAI, OpenRouter, Ollama, LM Studio, vLLM, llama.cpp or a
                    gateway.</ng-container
                  >
                }
              </clr-control-helper>
            </clr-radio-container>
            <clr-input-container>
              <label i18n="@@ai.url">URL</label>
              <input
                clrInput
                name="url"
                [(ngModel)]="c.url"
                (blur)="loadModels()"
                [placeholder]="
                  c.provider === 'anthropic' ? anthropicUrl : 'http://ollama.lan:11434/v1'
                "
                autocomplete="off"
                spellcheck="false"
                class="wide"
              />
              <clr-control-helper>
                @if (c.provider === 'anthropic') {
                  <ng-container i18n="@@ai.urlAnthropic"
                    >Empty for {{ anthropicUrl }}; for a gateway, its Anthropic endpoint, such as
                    https://gateway/anthropic.</ng-container
                  >
                } @else {
                  <ng-container i18n="@@ai.urlOpenai"
                    >The API's base, usually ending in /v1.</ng-container
                  >
                }
              </clr-control-helper>
            </clr-input-container>
            <clr-password-container>
              <label i18n="@@ai.key">API key</label>
              <input
                clrPassword
                name="apiKey"
                [(ngModel)]="apiKey"
                (blur)="apiKey && loadModels()"
                autocomplete="new-password"
                [placeholder]="c.hasKey ? storedKeep : optional"
              />
              <clr-control-helper i18n="@@ai.keyHelp"
                >Stored encrypted; local servers usually need none.</clr-control-helper
              >
            </clr-password-container>
            @if (c.hasKey && !apiKey) {
              <clr-checkbox-container>
                <label></label>
                <clr-checkbox-wrapper>
                  <input type="checkbox" clrCheckbox name="clearKey" [(ngModel)]="clearKey" />
                  <label i18n="@@ai.clearKey">Remove the stored key</label>
                </clr-checkbox-wrapper>
              </clr-checkbox-container>
            }
            <div class="clr-form-control clr-row">
              <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@ai.modelLabel"
                >Model</label
              >
              <div class="clr-control-container clr-col-12 clr-col-md-9">
                <nfa-model-picker [models]="models()" [(value)]="c.model" />
                <span class="clr-subtext model-help">
                  @if (loadingModels()) {
                    <span class="spinner spinner-inline"></span>
                    <ng-container i18n="@@ai.loadingModels">Loading models…</ng-container>
                  } @else if (modelsError()) {
                    <span class="bad">{{ modelsError() }}</span>
                  } @else if (models().length) {
                    <ng-container i18n="@@ai.modelsCount"
                      >{{ models().length }} models offered.</ng-container
                    >
                  } @else {
                    <ng-container i18n="@@ai.modelsHint"
                      >Models are listed once the URL (and key) are set.</ng-container
                    >
                  }
                  <button
                    type="button"
                    class="btn btn-sm btn-link reload"
                    (click)="loadModels()"
                    [disabled]="loadingModels()"
                    i18n="@@ai.reloadModels"
                  >
                    Reload
                  </button>
                </span>
              </div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header" i18n="@@ai.privacy">What is sent</div>
          <div class="card-block">
            <clr-checkbox-container>
              <label i18n="@@ai.names">Names</label>
              <clr-checkbox-wrapper>
                <input type="checkbox" clrCheckbox name="sendNames" [(ngModel)]="c.sendNames" />
                <label i18n="@@ai.sendNames"
                  >Send exporter, device, inventory and threat feed names</label
                >
              </clr-checkbox-wrapper>
              <clr-control-helper i18n="@@ai.sendNamesHelp"
                >So the model can write host:waldorf for "Waldorf". Off sends only the query
                language and your prompt. Flow data is never sent.</clr-control-helper
              >
            </clr-checkbox-container>
          </div>
        </div>

        <div class="card">
          <div class="card-header" i18n="@@ai.testTitle">Test</div>
          <div class="card-block">
            <button
              type="button"
              class="btn btn-outline"
              (click)="test()"
              [clrLoading]="testing()"
              [disabled]="!c.model"
              i18n="@@ai.test"
            >
              Write a sample query
            </button>
            <p class="hint" i18n="@@ai.testHelp">
              Asks for "web traffic to other countries than the US in the last day, excluding DNS"
              with the settings above, saved or not.
            </p>
            @if (testResult(); as t) {
              <div class="result">
                <code>{{ t.result.query }}</code>
                @if (t.result.range) {
                  <span class="label">{{ t.result.range }}</span>
                }
                <span class="muted">· {{ seconds(t.ms) }}</span>
                @if (t.result.explanation) {
                  <div class="muted">{{ t.result.explanation }}</div>
                }
                @if (t.result.error; as e) {
                  <div class="bad">
                    {{ e.error }}
                    @if (e.hint) {
                      &nbsp;· {{ e.hint }}
                    }
                  </div>
                }
              </div>
            }
            @if (testError()) {
              <div class="result bad">
                <cds-icon shape="error-standard" status="danger"></cds-icon> {{ testError() }}
              </div>
            }
          </div>
        </div>

        <div class="actions">
          <button
            type="submit"
            class="btn btn-primary"
            [clrLoading]="busy()"
            [disabled]="!dirty()"
            i18n="@@common.save"
          >
            Save
          </button>
          <button
            type="button"
            class="btn btn-outline"
            (click)="load()"
            [disabled]="!dirty()"
            i18n="@@common.revert"
          >
            Revert
          </button>
          @if (dirty()) {
            <span class="unsaved"
              ><cds-icon shape="exclamation-triangle"></cds-icon>
              <ng-container i18n="@@enrichment.unsaved">Unsaved changes.</ng-container></span
            >
          }
        </div>
      </form>
    }
  `,
  styles: `
    .ai-form {
      max-width: 880px;
    }
    .ai-form .card:first-child {
      margin-top: 0;
    }
    .alert {
      margin: 0 0 16px;
      max-width: 880px;
    }
    input.wide {
      width: 28rem;
      max-width: 100%;
    }
    .model-help {
      display: block;
      margin-top: 4px;
    }
    .reload {
      margin: 0 0 0 6px;
      padding: 0;
      min-width: 0;
      height: auto;
      line-height: inherit;
    }
    .hint {
      font-size: 12px;
      color: var(--cds-alias-typography-color-300);
      margin-top: 6px;
    }
    .result {
      margin-top: 10px;
      font-size: 13px;
      word-break: break-word;
    }
    .result code {
      font-size: 13px;
    }
    .bad {
      color: var(--cds-alias-status-danger);
    }
    .muted {
      color: var(--cds-alias-typography-color-300);
    }
    .actions {
      margin-top: 16px;
      display: flex;
      align-items: center;
      gap: 4px;
      flex-wrap: wrap;
    }
    .unsaved {
      font-size: 13px;
      color: var(--cds-alias-status-warning-shade, #8c5c00);
      margin-left: 8px;
    }
  `,
})
export class AISettingsPage {
  private api = inject(Api);
  readonly c = signal<AISettings | null>(null);
  readonly models = signal<{ id: string; name?: string }[]>([]);
  readonly loadingModels = signal(false);
  readonly modelsError = signal('');
  readonly busy = signal(false);
  readonly testing = signal(false);
  readonly saved = signal(false);
  readonly error = signal('');
  readonly testResult = signal<{ result: AIQueryResult; ms: number } | null>(null);
  readonly testError = signal('');
  readonly anthropicUrl = ANTHROPIC_URL;
  readonly storedKeep = $localize`:@@dataSources.storedKeep:Stored · leave empty to keep`;
  readonly optional = $localize`:@@ai.optional:Optional`;
  apiKey = '';
  clearKey = false;
  private savedJson = '';
  private modelsFor = '';
  private modelsSeq = 0;

  constructor() {
    this.load();
  }

  dirty() {
    const c = this.c();
    return !!c && (JSON.stringify(c) !== this.savedJson || !!this.apiKey || this.clearKey);
  }

  private form(): AISettings {
    return { ...this.c()!, apiKey: this.apiKey, clearKey: this.clearKey };
  }

  seconds = (ms: number) => `${(ms / 1000).toFixed(1)} s`;

  setProvider(p: AISettings['provider']) {
    const c = this.c();
    if (!c || c.provider === p) return;
    c.provider = p;
    c.model = '';
    if (p === 'openai' && c.url === ANTHROPIC_URL) c.url = '';
    this.models.set([]);
    this.modelsFor = '';
    this.loadModels();
  }

  /** Lists the endpoint's models (again only when the URL or key changed). */
  async loadModels(force = false) {
    const c = this.c();
    if (!c || (c.provider === 'openai' && !c.url.trim())) return;
    const key = `${c.provider}|${c.url.trim()}|${this.apiKey}|${this.clearKey}`;
    if (!force && key === this.modelsFor && this.models().length) return;
    this.modelsFor = key;
    const seq = ++this.modelsSeq; // only the newest request counts
    this.loadingModels.set(true);
    this.modelsError.set('');
    try {
      const list = await this.api.aiModels(this.form());
      if (seq !== this.modelsSeq) return;
      this.models.set(list);
      if (
        !c.model &&
        c.provider === 'anthropic' &&
        list.some((m) => m.id === ANTHROPIC_DEFAULT_MODEL)
      ) {
        c.model = ANTHROPIC_DEFAULT_MODEL;
      }
    } catch (err) {
      if (seq !== this.modelsSeq) return;
      this.models.set([]);
      this.modelsError.set(errorMessage(err));
    } finally {
      if (seq === this.modelsSeq) this.loadingModels.set(false);
    }
  }

  async load() {
    this.saved.set(false);
    this.error.set('');
    try {
      const c = await this.api.aiSettings();
      this.c.set(c);
      this.savedJson = JSON.stringify(c);
      this.apiKey = '';
      this.clearKey = false;
      if (c.url || c.hasKey) this.loadModels(true);
    } catch (err) {
      this.error.set(errorMessage(err));
    }
  }

  async save() {
    this.busy.set(true);
    this.saved.set(false);
    this.error.set('');
    try {
      const c = await this.api.saveAISettings(this.form());
      this.c.set(c);
      this.savedJson = JSON.stringify(c);
      this.apiKey = '';
      this.clearKey = false;
      this.saved.set(true);
      this.api.meta(true); // query bars pick up the AI button
    } catch (err) {
      this.error.set(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  async test() {
    this.testing.set(true);
    this.testResult.set(null);
    this.testError.set('');
    try {
      this.testResult.set(await this.api.testAI(this.form()));
    } catch (err) {
      this.testError.set(errorMessage(err));
    } finally {
      this.testing.set(false);
    }
  }
}
