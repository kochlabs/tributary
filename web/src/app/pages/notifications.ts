import { Component, computed, effect, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, Channel, errorMessage, NoticeRouting } from '../core/api';
import { ago, dateTime } from '../core/format';
import { loader, trackByKey } from '../core/util';

type ChannelType = Channel['type'];

/** Channel types: a card in the chooser and a section in the editor each. */
const TYPES: { id: ChannelType; label: string; description: string }[] = [
  {
    id: 'webhook',
    label: 'Webhook',
    description: $localize`:@@notify.webhookDescription:JSON to any URL, signed per the Standard Webhooks spec: SIEMs, automation tools, your own scripts.`,
  },
  {
    id: 'telegram',
    label: 'Telegram',
    description: $localize`:@@notify.telegramDescription:Messages from your own bot to you or a group; reports arrive as PDFs.`,
  },
];

const EVENTS: Record<string, string> = {
  'report.completed': $localize`:@@notify.event.reportCompleted:A report run completes`,
  'report.failed': $localize`:@@notify.event.reportFailed:A report run fails`,
  test: $localize`:@@notify.event.test:Test`,
};

const blank = (type: ChannelType): Partial<Channel> => ({
  name: type === 'telegram' ? 'Telegram' : 'Webhook',
  type,
  enabled: true,
  url: '',
  secret: '',
  chatId: '',
});

/** Notification channels: webhooks and Telegram (Configuration → Notifications). */
@Component({
  selector: 'nfa-notifications',
  imports: [ClarityModule, FormsModule, RouterLink],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.notifications">Notifications</h2>
        <p class="subtitle" i18n="@@notify.subtitle3">
          Where notifications go: webhooks and Telegram. Notices, threat feeds and reports choose
          their channels. Delivered in the background and retried for a day.
        </p>
      </div>
    </div>

    @if (list.error() || pageError()) {
      <div class="alert alert-danger" role="alert">
        <div class="alert-items">
          <div class="alert-item static">
            <span class="alert-text">{{ pageError() || list.error() }}</span>
          </div>
        </div>
      </div>
    }
    @if (info()) {
      <div class="alert alert-success" role="alert">
        <div class="alert-items">
          <div class="alert-item static">
            <span class="alert-text">{{ info() }}</span>
          </div>
        </div>
      </div>
    }
    @if (list.value(); as l) {
      @if (!l.publicUrl && l.channels.length) {
        <p class="hint">
          <cds-icon shape="info-standard"></cds-icon>
          <ng-container i18n="@@notify.noPublicUrl"
            >Messages have no links back to Tributary until its address is set under
            <a routerLink="/admin/settings">Configuration → Settings</a>.</ng-container
          >
        </p>
      }
    }

    <div class="toolbar">
      <div>
        <button class="btn btn-primary" (click)="chooserOpen.set(true)">
          <cds-icon shape="plus"></cds-icon>
          <ng-container i18n="@@notify.add">Add channel</ng-container>
        </button>
        <button class="btn btn-outline" [disabled]="!selected()" (click)="openEdit(selected()!)">
          <cds-icon shape="pencil"></cds-icon>
          <ng-container i18n="@@notify.edit">Edit</ng-container>
        </button>
        <button
          class="btn btn-outline"
          [disabled]="!selected() || testing()"
          [clrLoading]="testing()"
          (click)="testSaved(selected()!)"
        >
          <cds-icon shape="play"></cds-icon>
          <ng-container i18n="@@notify.sendTest">Send test</ng-container>
        </button>
        <button
          class="btn btn-outline"
          [disabled]="!selected()"
          (click)="confirmDelete.set(selected()!)"
        >
          <cds-icon shape="trash"></cds-icon>
          <ng-container i18n="@@notify.delete">Delete</ng-container>
        </button>
      </div>
      <button
        class="btn btn-link btn-icon"
        (click)="reload()"
        aria-label="Refresh"
        i18n-aria-label="@@common.refresh"
      >
        <cds-icon shape="refresh"></cds-icon>
      </button>
    </div>

    <clr-datagrid
      class="datagrid-compact"
      clrDgSelectionType="single"
      [clrDgSelected]="selectedList()"
      (clrDgSelectedChange)="selectedId.set($event[0]?.id)"
      [clrDgLoading]="list.loading()"
    >
      <clr-dg-column i18n="@@notify.name">Name</clr-dg-column>
      <clr-dg-column i18n="@@notify.type">Type</clr-dg-column>
      <clr-dg-column i18n="@@notify.destination">Destination</clr-dg-column>
      <clr-dg-column i18n="@@notify.status">Status</clr-dg-column>
      <clr-dg-row
        *clrDgItems="let c of list.value()?.channels ?? []; trackBy: byId"
        [clrDgItem]="c"
      >
        <clr-dg-cell
          >{{ c.name }}
          @if (!c.enabled) {
            <span class="label" i18n="@@notify.disabled">disabled</span>
          }
        </clr-dg-cell>
        <clr-dg-cell>{{ typeLabel(c.type) }}</clr-dg-cell>
        <clr-dg-cell class="dest">{{
          c.type === 'telegram' ? chatLabel + ' ' + c.chatId : c.url
        }}</clr-dg-cell>
        <clr-dg-cell>
          @if (c.lastError) {
            <span class="err" [title]="c.lastError"
              ><cds-icon shape="exclamation-triangle" status="danger"></cds-icon>
              {{ c.lastError }}</span
            >
          } @else if (c.lastSuccess) {
            <ng-container i18n="@@notify.lastSent">sent {{ ago(c.lastSuccess) }}</ng-container>
          } @else {
            <span class="muted" i18n="@@notify.nothingYet">nothing sent yet</span>
          }
        </clr-dg-cell>
      </clr-dg-row>
      <clr-dg-placeholder i18n="@@notify.placeholder"
        >No channels. Add a webhook or Telegram to hear about notices and
        reports.</clr-dg-placeholder
      >
    </clr-datagrid>

    @if (selected(); as c) {
      <div class="card deliveries">
        <div class="card-header">
          <ng-container i18n="@@notify.recent">Recent deliveries</ng-container>
          <span class="muted small">{{ c.name }}</span>
        </div>
        <div class="card-block">
          <table class="table table-compact">
            <thead>
              <tr>
                <th class="left" i18n="@@notify.col.when">Queued</th>
                <th class="left" i18n="@@notify.col.event">Event</th>
                <th class="left" i18n="@@notify.col.result">Result</th>
              </tr>
            </thead>
            <tbody>
              @for (d of deliveries.value() ?? []; track d.id) {
                <tr>
                  <td class="left">{{ dt(d.createdAt) }}</td>
                  <td class="left">{{ eventLabel(d.eventType) }}</td>
                  <td class="left">
                    @switch (d.status) {
                      @case ('delivered') {
                        <cds-icon shape="check-circle" status="success"></cds-icon>
                        <ng-container i18n="@@notify.delivered">delivered</ng-container>
                        @if (d.attempts > 1) {
                          <span class="muted" i18n="@@notify.afterAttempts"
                            >after {{ d.attempts }} attempts</span
                          >
                        }
                      }
                      @case ('pending') {
                        <cds-icon shape="clock"></cds-icon>
                        <ng-container i18n="@@notify.retrying"
                          >retrying {{ dt(d.nextAttempt) }}</ng-container
                        >
                        <span class="err small">{{ d.lastError }}</span>
                      }
                      @default {
                        <span class="err"
                          ><cds-icon shape="error-standard" status="danger"></cds-icon>
                          {{ d.lastError }}</span
                        >
                      }
                    }
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="3" class="left muted" i18n="@@notify.noDeliveries">
                    Nothing sent through this channel yet.
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </div>
    }

    @if (list.value(); as l) {
      <div class="card routing">
        <div class="card-header" i18n="@@notify.noticesTitle">Appliance notices</div>
        <div class="card-block">
          <p class="muted small" i18n="@@notify.noticesHelp">
            Notices (disk space, silent exporters, certificates, failed backups, …) are sent when
            they appear and when they clear. Threat feed matches are sent per feed, under
            <a routerLink="/security/threat-feeds">Security → Threat Feeds</a>.
          </p>
          @if (l.channels.length) {
            <form clrForm clrLayout="horizontal" (ngSubmit)="saveRouting()">
              <clr-select-container>
                <label i18n="@@notify.noticeLevel">Send</label>
                <select clrSelect name="routingLevel" [(ngModel)]="routing.level">
                  <option value="info" i18n="@@notify.level.info">Information and up</option>
                  <option value="warning" i18n="@@notify.level.warning">Warnings and up</option>
                  <option value="danger" i18n="@@notify.level.danger">Problems only</option>
                </select>
              </clr-select-container>
              <clr-checkbox-container>
                <label i18n="@@notify.noticeChannels">To channels</label>
                @for (c of l.channels; track c.id) {
                  <clr-checkbox-wrapper>
                    <input
                      type="checkbox"
                      clrCheckbox
                      [name]="'rt-' + c.id"
                      [checked]="routing.channels.includes(c.id)"
                      (change)="toggleRouting(c.id)"
                    />
                    <label>{{ c.name }}</label>
                  </clr-checkbox-wrapper>
                }
              </clr-checkbox-container>
              <button
                type="submit"
                class="btn btn-sm btn-primary"
                [clrLoading]="savingRouting()"
                i18n="@@common.save"
              >
                Save
              </button>
            </form>
          } @else {
            <p class="muted" i18n="@@notify.noticesNoChannels">Add a channel first.</p>
          }
        </div>
      </div>
    }

    <!-- Type chooser -->
    <clr-modal
      [clrModalOpen]="chooserOpen()"
      (clrModalOpenChange)="chooserOpen.set($event)"
      clrModalSize="lg"
    >
      <h3 class="modal-title" i18n="@@notify.addTitle">Add notification channel</h3>
      <div class="modal-body">
        <div class="types">
          @for (t of types; track t.id) {
            <button class="type-card" (click)="openNew(t.id)">
              <h4>{{ t.label }}</h4>
              <p>{{ t.description }}</p>
            </button>
          }
        </div>
      </div>
      <div class="modal-footer">
        <button
          type="button"
          class="btn btn-outline"
          (click)="chooserOpen.set(false)"
          i18n="@@common.cancel"
        >
          Cancel
        </button>
      </div>
    </clr-modal>

    <!-- Channel editor: common settings, then the type's destination -->
    <clr-modal
      [clrModalOpen]="!!editing()"
      (clrModalOpenChange)="!$event && editing.set(null)"
      clrModalSize="lg"
      [clrModalStaticBackdrop]="true"
    >
      <h3 class="modal-title">
        @if (editing()?.id) {
          <ng-container i18n="@@notify.editTypeTitle"
            >Edit {{ typeLabel(editing()?.type) }} channel</ng-container
          >
        } @else {
          <ng-container i18n="@@notify.addTypeTitle"
            >Add {{ typeLabel(editing()?.type) }} channel</ng-container
          >
        }
      </h3>
      <div class="modal-body">
        @if (editing(); as e) {
          <form clrForm clrLayout="horizontal" clrLabelSize="3" id="chform" (ngSubmit)="save()">
            <clr-input-container>
              <label i18n="@@notify.name">Name</label>
              <input clrInput name="name" [(ngModel)]="e.name" required maxlength="64" />
            </clr-input-container>
            <clr-toggle-container>
              <label i18n="@@notify.statusLabel">Status</label>
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="enabled" [(ngModel)]="e.enabled" />
                <label i18n="@@notify.enabled">Enabled</label>
              </clr-toggle-wrapper>
            </clr-toggle-container>

            <div class="section" i18n="@@notify.destinationSection">Destination</div>
            @switch (e.type) {
              @case ('webhook') {
                <clr-input-container>
                  <label i18n="@@notify.url">URL</label>
                  <input
                    clrInput
                    name="url"
                    [(ngModel)]="e.url"
                    required
                    placeholder="https://example.com/hooks/tributary"
                    class="wide"
                    autocomplete="off"
                    spellcheck="false"
                  />
                  <clr-control-helper i18n="@@notify.urlHelp"
                    >Receives a JSON POST per event. HTTPS certificates are checked against the
                    system CAs and those under Appliance → Certificates.</clr-control-helper
                  >
                </clr-input-container>
                <div class="clr-form-control clr-row">
                  <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@notify.signing"
                    >Signing</label
                  >
                  <div class="clr-control-container clr-col-12 clr-col-md-9">
                    @if (e.id) {
                      <button
                        type="button"
                        class="btn btn-sm btn-outline"
                        (click)="confirmRegen.set(e.id!)"
                        i18n="@@notify.regenerate"
                      >
                        Regenerate secret
                      </button>
                    }
                    <span class="clr-subtext" i18n="@@notify.signingHelp"
                      >Each request carries webhook-id, webhook-timestamp and webhook-signature
                      headers (Standard Webhooks): verify them with any Standard Webhooks library
                      and the secret. The secret is shown once, when the channel is created.</span
                    >
                  </div>
                </div>
              }
              @case ('telegram') {
                <clr-password-container>
                  <label i18n="@@notify.botToken">Bot token</label>
                  <input
                    clrPassword
                    name="token"
                    [(ngModel)]="e.secret"
                    autocomplete="new-password"
                    [placeholder]="e.hasSecret ? storedKeep : '123456789:AA…'"
                    class="wide"
                  />
                  <clr-control-helper i18n="@@notify.botTokenHelp"
                    >Create a bot with @BotFather in Telegram and paste its token. Stored
                    encrypted.</clr-control-helper
                  >
                </clr-password-container>
                <clr-input-container>
                  <label i18n="@@notify.chatId">Chat ID</label>
                  <input
                    clrInput
                    name="chatId"
                    [(ngModel)]="e.chatId"
                    required
                    placeholder="123456789"
                    autocomplete="off"
                  />
                  <clr-control-helper i18n="@@notify.chatIdHelp"
                    >Send your bot a message, then open api.telegram.org/bot&lt;token&gt;/getUpdates
                    and use message.chat.id. Groups have negative IDs.</clr-control-helper
                  >
                </clr-input-container>
              }
            }
          </form>
          @if (test(); as t) {
            @if (t.ok) {
              <div class="alert alert-success alert-sm" role="alert">
                <div class="alert-items">
                  <div class="alert-item static">
                    <span class="alert-text" i18n="@@notify.testOk">Test sent.</span>
                  </div>
                </div>
              </div>
            } @else {
              <div class="alert alert-danger alert-sm" role="alert">
                <div class="alert-items">
                  <div class="alert-item static">
                    <span class="alert-text">{{ t.error }}</span>
                  </div>
                </div>
              </div>
            }
          }
          @if (formError()) {
            <div class="alert alert-danger alert-sm" role="alert">
              <div class="alert-items">
                <div class="alert-item static">
                  <span class="alert-text">{{ formError() }}</span>
                </div>
              </div>
            </div>
          }
        }
      </div>
      <div class="modal-footer">
        <button
          type="button"
          class="btn btn-outline"
          (click)="runTest()"
          [clrLoading]="testing()"
          [disabled]="!canTest()"
          i18n="@@notify.sendTest"
        >
          Send test
        </button>
        <button
          type="button"
          class="btn btn-outline"
          (click)="editing.set(null)"
          i18n="@@common.cancel"
        >
          Cancel
        </button>
        <button
          type="submit"
          form="chform"
          class="btn btn-primary"
          [clrLoading]="busy()"
          [disabled]="!editing()?.name"
          i18n="@@common.save"
        >
          Save
        </button>
      </div>
    </clr-modal>

    <!-- A webhook's secret, shown once -->
    <clr-modal
      [clrModalOpen]="!!secret()"
      (clrModalOpenChange)="!$event && secret.set('')"
      clrModalSize="lg"
      [clrModalStaticBackdrop]="true"
    >
      <h3 class="modal-title" i18n="@@notify.secretTitle">Signing secret</h3>
      <div class="modal-body">
        <p i18n="@@notify.secretText">
          Copy it into the receiving side now: it won't be shown again.
        </p>
        <div class="secret">
          <code>{{ secret() }}</code>
          <button type="button" class="btn btn-link btn-sm" (click)="copy(secret())">
            {{ copied() ? copiedLabel : copyLabel }}
          </button>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-primary" (click)="secret.set('')" i18n="@@notify.done">
          Done
        </button>
      </div>
    </clr-modal>

    <clr-modal
      [clrModalOpen]="!!confirmRegen()"
      (clrModalOpenChange)="!$event && confirmRegen.set(0)"
      clrModalSize="md"
    >
      <h3 class="modal-title" i18n="@@notify.regenTitle">Regenerate the signing secret?</h3>
      <div class="modal-body">
        <p i18n="@@notify.regenText">
          The receiving side rejects deliveries until it has the new secret.
        </p>
      </div>
      <div class="modal-footer">
        <button
          type="button"
          class="btn btn-outline"
          (click)="confirmRegen.set(0)"
          i18n="@@common.cancel"
        >
          Cancel
        </button>
        <button
          type="button"
          class="btn btn-danger"
          (click)="regenerate()"
          i18n="@@notify.regenerate"
        >
          Regenerate secret
        </button>
      </div>
    </clr-modal>

    <clr-modal
      [clrModalOpen]="!!confirmDelete()"
      (clrModalOpenChange)="!$event && confirmDelete.set(null)"
      clrModalSize="md"
    >
      <h3 class="modal-title" i18n="@@notify.deleteTitle">Delete {{ confirmDelete()?.name }}?</h3>
      <div class="modal-body">
        <p i18n="@@notify.deleteText">Nothing more is sent to it; queued deliveries are dropped.</p>
      </div>
      <div class="modal-footer">
        <button
          type="button"
          class="btn btn-outline"
          (click)="confirmDelete.set(null)"
          i18n="@@common.cancel"
        >
          Cancel
        </button>
        <button type="button" class="btn btn-danger" (click)="remove()" i18n="@@notify.delete">
          Delete
        </button>
      </div>
    </clr-modal>
  `,
  styles: `
    .alert {
      margin: 0 0 16px;
    }
    .modal-body .alert {
      margin: 12px 0 0;
    }
    .toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }
    .toolbar .btn {
      margin: 0 6px 0 0;
    }
    .dest {
      word-break: break-all;
    }
    .err {
      color: var(--cds-alias-status-danger);
    }
    .muted {
      color: var(--cds-alias-typography-color-300);
    }
    .small {
      font-size: 12px;
    }
    .label {
      margin-left: 6px;
    }
    .hint {
      font-size: 13px;
      margin: 0 0 12px;
    }
    .routing {
      margin-top: 24px;
      max-width: 48rem;
    }
    .routing .card-block > p:first-child {
      margin-top: 0;
    }
    .routing .btn {
      margin-top: 12px;
    }
    .deliveries {
      margin-top: 16px;
    }
    .deliveries table {
      margin: 0;
    }
    .left {
      text-align: left;
    }
    .types {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
    }
    .type-card {
      text-align: left;
      padding: 18px 20px;
      border: 1px solid var(--cds-alias-object-border-color);
      border-radius: 4px;
      background: var(--cds-alias-object-container-background);
      cursor: pointer;
      font: inherit;
      color: inherit;
    }
    .type-card:hover {
      border-color: var(--cds-alias-status-info);
    }
    .type-card h4 {
      margin: 0 0 6px;
    }
    .type-card p {
      margin: 0;
      font-size: 13px;
      color: var(--cds-alias-typography-color-300);
    }
    .section {
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-size: 12px;
      color: var(--cds-alias-typography-color-300);
      margin: 22px 0 0;
    }
    .secret {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .secret code {
      font-size: 12px;
      word-break: break-all;
    }
    .secret .btn {
      margin: 0;
      flex: none;
    }
    input.wide {
      width: 26rem;
      max-width: 100%;
    }
    @media (max-width: 900px) {
      .types {
        grid-template-columns: 1fr;
      }
    }
  `,
})
export class Notifications {
  readonly byId = trackByKey<{ id: number }>((c) => c.id);
  private api = inject(Api);
  readonly types = TYPES;
  readonly list = loader(
    () => true,
    () => this.api.channels(),
  );
  readonly selectedId = signal<number | undefined>(undefined);
  readonly selected = computed(() =>
    this.list.value()?.channels.find((c) => c.id === this.selectedId()),
  );
  readonly selectedList = computed(() => {
    const c = this.selected();
    return c ? [c] : [];
  });
  readonly deliveries = loader(
    () => this.selectedId(),
    (id) => this.api.channelDeliveries(id),
  );
  readonly chooserOpen = signal(false);
  readonly editing = signal<Partial<Channel> | null>(null);
  readonly confirmDelete = signal<Channel | null>(null);
  readonly confirmRegen = signal(0);
  readonly secret = signal('');
  readonly copied = signal(false);
  readonly test = signal<{ ok: boolean; error?: string } | null>(null);
  readonly busy = signal(false);
  readonly testing = signal(false);
  readonly formError = signal('');
  readonly pageError = signal('');
  readonly info = signal('');
  readonly storedKeep = $localize`:@@dataSources.storedKeep:Stored · leave empty to keep`;
  readonly chatLabel = $localize`:@@notify.chat:chat`;
  readonly copyLabel = $localize`:@@identitySources.copy:Copy`;
  readonly copiedLabel = $localize`:@@identitySources.copied:Copied`;
  ago = ago;
  dt = dateTime;

  typeLabel(t?: string) {
    return TYPES.find((x) => x.id === t)?.label ?? t ?? '';
  }

  eventLabel(e: string) {
    return EVENTS[e] ?? e;
  }

  reload() {
    this.list.reload();
    this.deliveries.reload();
  }

  /** Whether the destination is complete enough to test, by type. */
  canTest() {
    const e = this.editing();
    if (!e) return false;
    switch (e.type) {
      case 'webhook':
        return !!e.url;
      case 'telegram':
        return !!e.chatId && (!!e.secret || !!e.hasSecret);
    }
    return false;
  }

  openNew(type: ChannelType) {
    this.chooserOpen.set(false);
    this.editing.set(blank(type));
    this.test.set(null);
    this.formError.set('');
  }

  openEdit(c: Channel) {
    this.editing.set({ ...c, secret: '' });
    this.test.set(null);
    this.formError.set('');
  }

  async runTest() {
    const e = this.editing();
    if (!e) return;
    this.testing.set(true);
    this.test.set(null);
    try {
      this.test.set(await this.api.testChannel(e));
    } catch (err) {
      this.test.set({ ok: false, error: errorMessage(err) });
    } finally {
      this.testing.set(false);
    }
  }

  async testSaved(c: Channel) {
    this.testing.set(true);
    this.pageError.set('');
    try {
      const r = await this.api.testChannel(c);
      if (r.ok) this.flash($localize`:@@notify.testSentTo:Test sent to ${c.name}:name:.`);
      else this.pageError.set(r.error ?? '');
    } catch (err) {
      this.pageError.set(errorMessage(err));
    } finally {
      this.testing.set(false);
    }
  }

  /** The notice routing being edited, from the last load. */
  routing: NoticeRouting = { level: 'warning', channels: [] };
  readonly savingRouting = signal(false);
  private readonly syncRouting = effect(() => {
    const r = this.list.value()?.notices;
    if (r) this.routing = { level: r.level, channels: [...r.channels] };
  });

  toggleRouting(id: number) {
    const cur = this.routing.channels;
    this.routing.channels = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
  }

  async saveRouting() {
    this.savingRouting.set(true);
    this.pageError.set('');
    try {
      this.routing = await this.api.saveNoticeRouting(this.routing);
      this.flash($localize`:@@notify.routingSaved:Notice settings saved.`);
    } catch (err) {
      this.pageError.set(errorMessage(err));
    } finally {
      this.savingRouting.set(false);
    }
  }

  async save() {
    const e = this.editing();
    if (!e) return;
    this.busy.set(true);
    this.formError.set('');
    try {
      const saved = await this.api.saveChannel(e);
      this.editing.set(null);
      this.selectedId.set(saved.id);
      if (saved.secret) this.secret.set(saved.secret);
      this.list.reload();
    } catch (err) {
      this.formError.set(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  async regenerate() {
    const id = this.confirmRegen();
    this.confirmRegen.set(0);
    if (!id) return;
    try {
      const r = await this.api.regenerateChannelSecret(id);
      this.editing.set(null);
      this.secret.set(r.secret);
    } catch (err) {
      this.formError.set(errorMessage(err));
    }
  }

  async remove() {
    const c = this.confirmDelete();
    this.confirmDelete.set(null);
    if (!c) return;
    try {
      await this.api.deleteChannel(c.id);
      this.selectedId.set(undefined);
      this.pageError.set('');
    } catch (err) {
      this.pageError.set(errorMessage(err));
    }
    this.list.reload();
  }

  async copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      this.copied.set(true);
      setTimeout(() => this.copied.set(false), 2000);
    } catch {
      /* clipboard unavailable: the text is selectable */
    }
  }

  private flash(msg: string) {
    this.info.set(msg);
    setTimeout(() => this.info.set(''), 5000);
  }
}
