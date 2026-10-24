import { Component, computed, DestroyRef, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';
import { RouterLink } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { Api, Channel, errorMessage, Report, ReportRun } from '../core/api';
import { Auth } from '../core/auth';
import { ago, dateTime } from '../core/format';
import { loader, trackByKey } from '../core/util';
import { QueryBar } from '../shared/query-bar';

const TEMPLATES: Record<string, string> = {
  summary: $localize`:@@reports.template.summary:Network summary`,
  security: $localize`:@@reports.template.security:Security digest`,
};
const SECTIONS: Record<string, string> = {
  kpis: $localize`:@@reports.section.kpis:Headline figures`,
  traffic: $localize`:@@reports.section.traffic:Traffic over time`,
  services: $localize`:@@reports.section.services:Top services`,
  devices: $localize`:@@reports.section.devices:Top devices`,
  apps: $localize`:@@reports.section.apps:Applications`,
  countries: $localize`:@@reports.section.countries:Remote countries`,
  threats: $localize`:@@reports.section.threats:Threat feed matches`,
  exposure: $localize`:@@reports.section.exposure:Exposed services`,
  new_devices: $localize`:@@reports.section.newDevices:New devices`,
  exporters: $localize`:@@reports.section.exporters:Exporters`,
};
const PERIODS: { id: Report['period']; label: string }[] = [
  { id: 'yesterday', label: $localize`:@@reports.period.yesterday:Yesterday` },
  { id: 'last_week', label: $localize`:@@reports.period.lastWeek:Last week (Monday to Sunday)` },
  { id: 'last_month', label: $localize`:@@reports.period.lastMonth:Last month` },
  { id: 'last_24h', label: $localize`:@@reports.period.24h:Last 24 hours` },
  { id: 'last_7d', label: $localize`:@@reports.period.7d:Last 7 days` },
  { id: 'last_30d', label: $localize`:@@reports.period.30d:Last 30 days` },
];
const WEEKDAYS = [
  $localize`:@@reports.day.sun:Sunday`,
  $localize`:@@reports.day.mon:Monday`,
  $localize`:@@reports.day.tue:Tuesday`,
  $localize`:@@reports.day.wed:Wednesday`,
  $localize`:@@reports.day.thu:Thursday`,
  $localize`:@@reports.day.fri:Friday`,
  $localize`:@@reports.day.sat:Saturday`,
];
// The schedule matching a calendar period: run once the day, week or month ends.
const SCHEDULE_FOR: Partial<Record<Report['period'], Report['schedule']>> = {
  yesterday: 'daily',
  last_week: 'weekly',
  last_month: 'monthly',
};

const blank = (
  template: Report['template'] = 'summary',
  sections: string[] = [],
): Partial<Report> => ({
  name: TEMPLATES[template],
  template,
  sections,
  period: template === 'security' ? 'last_week' : 'last_7d',
  query: '',
  schedule: 'off',
  hour: 7,
  weekday: 1,
  monthday: 1,
  recipients: '',
  channels: [],
  keep: 12,
});

/** Saved reports, rendered as PDF on the appliance (Reports). */
@Component({
  selector: 'nfa-reports',
  imports: [ClarityModule, FormsModule, RouterLink, QueryBar],
  template: `
    <div class="page-header">
      <div>
        <h2 i18n="@@nav.reports">Reports</h2>
        <p class="subtitle" i18n="@@reports.subtitle3">
          PDF reports generated on the appliance, on demand or on a schedule.
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
      @if (!l.reports.length) {
        <div class="empty card">
          <div class="card-block">
            <cds-icon shape="file-group" size="xl"></cds-icon>
            <p i18n="@@reports.none">No reports yet.</p>
            @if (auth.isAdmin()) {
              <div>
                <button
                  class="btn btn-primary"
                  (click)="openEdit(undefined, 'summary')"
                  i18n="@@reports.createSummary"
                >
                  Create a network summary
                </button>
                <button
                  class="btn btn-outline"
                  (click)="openEdit(undefined, 'security')"
                  i18n="@@reports.createSecurity"
                >
                  Create a security digest
                </button>
              </div>
            } @else {
              <p class="muted" i18n="@@reports.askAdmin">An administrator can set reports up.</p>
            }
          </div>
        </div>
      } @else {
        <div class="toolbar">
          <div>
            @if (auth.isAdmin()) {
              <button class="btn btn-primary" (click)="openEdit()">
                <cds-icon shape="plus"></cds-icon>
                <ng-container i18n="@@reports.new">New report</ng-container>
              </button>
              <button
                class="btn btn-outline"
                [disabled]="!selected()"
                (click)="openEdit(selected())"
              >
                <cds-icon shape="pencil"></cds-icon>
                <ng-container i18n="@@reports.edit">Edit</ng-container>
              </button>
              <button
                class="btn btn-outline"
                [disabled]="!selected() || running()"
                [clrLoading]="running()"
                (click)="confirmRun.set(selected()!)"
              >
                <cds-icon shape="play"></cds-icon>
                <ng-container i18n="@@reports.runNow">Run now</ng-container>
              </button>
              <button
                class="btn btn-outline"
                [disabled]="!selected()"
                (click)="confirmDelete.set(selected()!)"
              >
                <cds-icon shape="trash"></cds-icon>
                <ng-container i18n="@@reports.delete">Delete</ng-container>
              </button>
            }
          </div>
          <button
            class="btn btn-link btn-icon"
            (click)="list.reload()"
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
          (clrDgSelectedChange)="select($event[0])"
        >
          <clr-dg-column i18n="@@reports.col.name">Name</clr-dg-column>
          <clr-dg-column i18n="@@reports.col.period">Period</clr-dg-column>
          <clr-dg-column i18n="@@reports.col.schedule">Schedule</clr-dg-column>
          <clr-dg-column i18n="@@reports.col.recipients">Email to</clr-dg-column>
          @if (auth.isAdmin()) {
            <clr-dg-column i18n="@@reports.col.channels">Send to</clr-dg-column>
          }
          <clr-dg-column i18n="@@reports.col.lastRun">Last run</clr-dg-column>
          <clr-dg-row *clrDgItems="let r of l.reports; trackBy: byId" [clrDgItem]="r">
            <clr-dg-cell
              >{{ r.name }}
              <div class="muted small">
                {{ templateLabel(r.template) }}
                @if (filterCount(r)) {
                  · <span [title]="r.query" i18n="@@reports.filtered">filtered</span>
                }
              </div></clr-dg-cell
            >
            <clr-dg-cell>{{ periodLabel(r.period) }}</clr-dg-cell>
            <clr-dg-cell
              >{{ scheduleLabel(r) }}
              @if (r.nextRun) {
                <div class="muted small" i18n="@@reports.next">next {{ dt(r.nextRun) }}</div>
              }
            </clr-dg-cell>
            <clr-dg-cell>
              @if (recipientCount(r); as n) {
                <span [title]="r.recipients"
                  ><ng-container i18n="@@reports.recipients">{n, plural,
                    =1 {1 recipient}
                    other {{{ n }} recipients}
                  }</ng-container></span
                >
              } @else {
                <span class="muted">–</span>
              }
            </clr-dg-cell>
            @if (auth.isAdmin()) {
              <clr-dg-cell>
                @for (n of channelNames(r); track $index) {
                  <div>{{ n }}</div>
                } @empty {
                  <span class="muted">–</span>
                }
              </clr-dg-cell>
            }
            <clr-dg-cell>
              @if (r.lastRun; as run) {
                @if (run.status === 'ok') {
                  <cds-icon shape="check-circle" status="success"></cds-icon>
                } @else {
                  <cds-icon
                    shape="error-standard"
                    status="danger"
                    [title]="run.error ?? ''"
                  ></cds-icon>
                }
                {{ ago(run.startedAt) }}
              } @else {
                <span class="muted" i18n="@@reports.never">never</span>
              }
            </clr-dg-cell>
          </clr-dg-row>
          <clr-dg-placeholder i18n="@@reports.placeholder">No reports.</clr-dg-placeholder>
        </clr-datagrid>
        @if (!l.emailEnabled && auth.isAdmin() && hasRecipients()) {
          <p class="hint">
            <cds-icon shape="exclamation-triangle" status="warning"></cds-icon>
            <ng-container i18n="@@reports.emailOff"
              >Email is turned off, so reports aren't sent; they are still kept here. Set it up
              under <a routerLink="/admin/email">Configuration → Email</a>.</ng-container
            >
          </p>
        }

        @if (selected(); as r) {
          <div class="card detail">
            <div class="card-header">
              <span>{{ r.name }}</span>
              <div class="btn-group btn-sm" role="group">
                <button
                  class="btn"
                  [class.btn-primary]="view() === 'preview'"
                  [class.btn-outline]="view() !== 'preview'"
                  (click)="setView('preview')"
                  i18n="@@reports.preview"
                >
                  Preview
                </button>
                <button
                  class="btn"
                  [class.btn-primary]="view() === 'history'"
                  [class.btn-outline]="view() !== 'history'"
                  (click)="setView('history')"
                  i18n="@@reports.history"
                >
                  History
                </button>
              </div>
            </div>
            @if (view() === 'preview') {
              <div class="card-block viewer">
                @if (pdf.loading()) {
                  <div class="state">
                    <span class="spinner spinner-md"></span>
                    <span i18n="@@reports.generating"
                      >Generating the report… longer periods take a while.</span
                    >
                  </div>
                } @else if (pdf.error()) {
                  <div class="state error">
                    <cds-icon shape="error-standard"></cds-icon> {{ pdf.error() }}
                  </div>
                } @else if (pdf.frame(); as u) {
                  <iframe [src]="u" [title]="r.name"></iframe>
                }
              </div>
              <div class="card-footer">
                <span class="muted small" i18n="@@reports.previewHint"
                  >The period as of now; nothing is kept or sent.</span
                >
                <button
                  class="btn btn-sm btn-link"
                  [disabled]="!pdf.url()"
                  (click)="pdf.save(fileName(r))"
                >
                  <cds-icon shape="download"></cds-icon>
                  <ng-container i18n="@@reports.download">Download PDF</ng-container>
                </button>
              </div>
            } @else {
              <div class="card-block">
                <table class="table table-compact runs">
                  <thead>
                    <tr>
                      <th class="left" i18n="@@reports.run.when">Run</th>
                      <th class="left" i18n="@@reports.run.period">Period</th>
                      <th class="left" i18n="@@reports.run.result">Result</th>
                      <th class="left" i18n="@@reports.run.emailed">Emailed</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    @for (run of runs.value() ?? []; track run.id) {
                      <tr>
                        <td class="left">
                          {{ dt(run.startedAt) }}
                          <div class="muted small">
                            {{ run.trigger === 'schedule' ? scheduledLabel : manualLabel }}
                          </div>
                        </td>
                        <td class="left">{{ dt(run.from) }} – {{ dt(run.to) }}</td>
                        <td class="left">
                          @if (run.status === 'ok') {
                            <cds-icon shape="check-circle" status="success"></cds-icon>
                            {{ kb(run.size) }}
                          } @else {
                            <span class="error-text"
                              ><cds-icon shape="error-standard" status="danger"></cds-icon>
                              {{ run.error }}</span
                            >
                          }
                        </td>
                        <td class="left small">{{ run.emailed || '–' }}</td>
                        <td>
                          @if (run.size) {
                            <button class="btn btn-sm btn-link" (click)="download(run, r)">
                              <cds-icon shape="download"></cds-icon> PDF
                            </button>
                          }
                        </td>
                      </tr>
                    } @empty {
                      <tr>
                        <td colspan="5" class="left muted" i18n="@@reports.noRuns">
                          Not run yet. Scheduled runs and Run now are kept here.
                        </td>
                      </tr>
                    }
                  </tbody>
                </table>
              </div>
            }
          </div>
        }
      }
    }

    <clr-modal
      [clrModalOpen]="!!editing()"
      (clrModalOpenChange)="!$event && editing.set(null)"
      clrModalSize="lg"
      [clrModalStaticBackdrop]="true"
    >
      <h3 class="modal-title">{{ editing()?.id ? editTitle : newTitle }}</h3>
      <div class="modal-body">
        @if (editing(); as e) {
          <form clrForm clrLayout="horizontal" clrLabelSize="3" id="reportform" (ngSubmit)="save()">
            <clr-input-container>
              <label i18n="@@reports.col.name">Name</label>
              <input
                clrInput
                name="name"
                [(ngModel)]="e.name"
                required
                maxlength="80"
                class="wide"
              />
            </clr-input-container>
            <clr-select-container>
              <label i18n="@@reports.template">Template</label>
              <select
                clrSelect
                name="template"
                [ngModel]="e.template"
                (ngModelChange)="setTemplate(e, $event)"
              >
                @for (t of templateIds; track t) {
                  <option [value]="t">{{ templateLabel(t) }}</option>
                }
              </select>
            </clr-select-container>
            <clr-checkbox-container>
              <label i18n="@@reports.sections">Sections</label>
              @for (sec of allSections(); track sec) {
                <clr-checkbox-wrapper>
                  <input
                    type="checkbox"
                    clrCheckbox
                    [name]="'sec-' + sec"
                    [checked]="e.sections!.includes(sec)"
                    (change)="toggleSection(e, sec)"
                  />
                  <label>{{ sectionLabel(sec) }}</label>
                </clr-checkbox-wrapper>
              }
            </clr-checkbox-container>
            <clr-select-container>
              <label i18n="@@reports.col.period">Period</label>
              <select
                clrSelect
                name="period"
                [ngModel]="e.period"
                (ngModelChange)="setPeriod(e, $event)"
              >
                @for (p of periods; track p.id) {
                  <option [value]="p.id">{{ p.label }}</option>
                }
              </select>
            </clr-select-container>
            <div class="clr-form-control clr-row">
              <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@reports.query"
                >Query</label
              >
              <div class="clr-control-container clr-col-12 clr-col-md-9">
                <nfa-query-bar [(query)]="editQuery" [live]="true" />
                <span class="clr-subtext" i18n="@@reports.queryHelp"
                  >Optional: limit the whole report to matching traffic, e.g.
                  exporter:core-router.</span
                >
              </div>
            </div>
            <clr-select-container>
              <label i18n="@@reports.col.schedule">Schedule</label>
              <select
                clrSelect
                name="schedule"
                [ngModel]="e.schedule"
                (ngModelChange)="setSchedule(e, $event)"
              >
                <option value="off" i18n="@@reports.schedule.off">Off: run on demand</option>
                <option value="daily" i18n="@@reports.schedule.daily">Daily</option>
                <option value="weekly" i18n="@@reports.schedule.weekly">Weekly</option>
                <option value="monthly" i18n="@@reports.schedule.monthly">Monthly</option>
              </select>
            </clr-select-container>
            @if (e.schedule !== 'off') {
              <div class="clr-form-control clr-row">
                <label class="clr-control-label clr-col-12 clr-col-md-3" i18n="@@reports.at"
                  >At</label
                >
                <div class="clr-control-container clr-col-12 clr-col-md-9 when">
                  @if (e.schedule === 'weekly') {
                    <select
                      class="clr-select"
                      name="weekday"
                      [(ngModel)]="e.weekday"
                      aria-label="Day of the week"
                      i18n-aria-label="@@reports.weekday"
                    >
                      @for (d of weekdays; track $index) {
                        <option [ngValue]="$index">{{ d }}</option>
                      }
                    </select>
                  }
                  @if (e.schedule === 'monthly') {
                    <span i18n="@@reports.dayOfMonth">day</span>
                    <select
                      class="clr-select"
                      name="monthday"
                      [(ngModel)]="e.monthday"
                      aria-label="Day of the month"
                      i18n-aria-label="@@reports.monthday"
                    >
                      @for (d of monthdays; track d) {
                        <option [ngValue]="d">{{ d }}</option>
                      }
                    </select>
                  }
                  <select
                    class="clr-select"
                    name="hour"
                    [(ngModel)]="e.hour"
                    aria-label="Hour"
                    i18n-aria-label="@@reports.hour"
                  >
                    @for (h of hours; track h) {
                      <option [ngValue]="h">{{ pad(h) }}:00</option>
                    }
                  </select>
                  <span class="muted small">{{ list.value()?.timezone }}</span>
                </div>
              </div>
            }
            <clr-textarea-container>
              <label i18n="@@reports.col.recipients">Email to</label>
              <textarea
                clrTextarea
                name="recipients"
                [(ngModel)]="e.recipients"
                rows="2"
                class="wide"
                placeholder="noc@example.com, cio@example.com"
              ></textarea>
              <clr-control-helper>
                @if (list.value()?.emailEnabled) {
                  <ng-container i18n="@@reports.recipientsHelp"
                    >Scheduled runs are emailed here as a PDF attachment. Leave empty to only keep
                    them on the appliance.</ng-container
                  >
                } @else {
                  <ng-container i18n="@@reports.recipientsEmailOff"
                    >Email is turned off (Configuration → Email): runs are kept on the appliance
                    only.</ng-container
                  >
                }
              </clr-control-helper>
            </clr-textarea-container>
            <clr-checkbox-container>
              <label i18n="@@reports.channels">Send to channels</label>
              @for (c of channelList(); track c.id) {
                <clr-checkbox-wrapper>
                  <input
                    type="checkbox"
                    clrCheckbox
                    [name]="'ch-' + c.id"
                    [checked]="e.channels!.includes(c.id)"
                    (change)="toggleChannel(e, c.id)"
                  />
                  <label
                    >{{ c.name }}
                    @if (!c.enabled) {
                      <span class="muted" i18n="@@notify.disabled">disabled</span>
                    }
                  </label>
                </clr-checkbox-wrapper>
              }
              <clr-control-helper>
                @if (channelList().length) {
                  <ng-container i18n="@@reports.channelsHelp"
                    >Scheduled runs, and failures, are sent here too. Telegram gets the
                    PDF.</ng-container
                  >
                } @else {
                  <ng-container i18n="@@reports.noChannels"
                    >No channels yet: add webhooks or Telegram under
                    <a routerLink="/admin/notifications">Configuration → Notifications</a
                    >.</ng-container
                  >
                }
              </clr-control-helper>
            </clr-checkbox-container>
            <clr-input-container>
              <label i18n="@@reports.keep">Keep</label>
              <input
                clrInput
                type="number"
                name="keep"
                [(ngModel)]="e.keep"
                min="1"
                max="100"
                class="short"
              />
              <clr-control-helper i18n="@@reports.keepHelp"
                >Runs kept on the appliance; older ones are deleted.</clr-control-helper
              >
            </clr-input-container>
          </form>
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
          (click)="editing.set(null)"
          i18n="@@common.cancel"
        >
          Cancel
        </button>
        <button
          type="submit"
          form="reportform"
          class="btn btn-primary"
          [clrLoading]="busy()"
          [disabled]="!editing()?.name?.trim() || !editing()?.sections?.length"
          i18n="@@common.save"
        >
          Save
        </button>
      </div>
    </clr-modal>

    <clr-modal
      [clrModalOpen]="!!confirmRun()"
      (clrModalOpenChange)="!$event && confirmRun.set(null)"
      clrModalSize="md"
    >
      <h3 class="modal-title" i18n="@@reports.runTitle">Run {{ confirmRun()?.name }} now?</h3>
      <div class="modal-body">
        <p i18n="@@reports.runText">
          The report is generated for its period as of now and kept in its history.
        </p>
        @if (canDeliver(confirmRun())) {
          <clr-checkbox-wrapper>
            <input type="checkbox" clrCheckbox id="runDeliver" [(ngModel)]="runDeliver" />
            <label for="runDeliver" i18n="@@reports.runDeliver"
              >Also send it to its recipients and channels</label
            >
          </clr-checkbox-wrapper>
        }
      </div>
      <div class="modal-footer">
        <button
          type="button"
          class="btn btn-outline"
          (click)="confirmRun.set(null)"
          i18n="@@common.cancel"
        >
          Cancel
        </button>
        <button type="button" class="btn btn-primary" (click)="run()" i18n="@@reports.runNow">
          Run now
        </button>
      </div>
    </clr-modal>

    <clr-modal
      [clrModalOpen]="!!confirmDelete()"
      (clrModalOpenChange)="!$event && confirmDelete.set(null)"
      clrModalSize="md"
    >
      <h3 class="modal-title" i18n="@@reports.deleteTitle">Delete {{ confirmDelete()?.name }}?</h3>
      <div class="modal-body">
        <p i18n="@@reports.deleteText">Its schedule stops and its kept runs are deleted.</p>
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
        <button type="button" class="btn btn-danger" (click)="remove()" i18n="@@reports.delete">
          Delete
        </button>
      </div>
    </clr-modal>
  `,
  styles: `
    .alert {
      margin: 0 0 16px;
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
    .muted {
      color: var(--cds-alias-typography-color-300);
    }
    .small {
      font-size: 12px;
    }
    .hint {
      font-size: 13px;
      margin-top: 8px;
    }
    .empty .card-block {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      padding: 48px 16px;
    }
    .empty .btn {
      margin: 4px;
    }
    .detail {
      margin-top: 16px;
    }
    .detail .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
    }
    .detail .btn-group {
      margin: 0;
    }
    .viewer {
      padding: 0;
      height: calc(100vh - 260px);
      min-height: 480px;
    }
    .state {
      height: 100%;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      color: var(--cds-alias-typography-color-300);
    }
    .state.error,
    .error-text {
      color: var(--cds-alias-status-danger);
    }
    iframe {
      display: block;
      width: 100%;
      height: 100%;
      border: 0;
    }
    .card-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .card-footer .btn {
      margin: 0;
    }
    .runs {
      margin: 0;
    }
    .left {
      text-align: left;
    }
    .when {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    input.wide,
    textarea.wide {
      width: 26rem;
      max-width: 100%;
    }
    input.short {
      width: 5rem;
    }
  `,
})
export class Reports {
  readonly byId = trackByKey<{ id: number }>((r) => r.id);
  readonly auth = inject(Auth);
  private api = inject(Api);
  readonly list = loader(
    () => true,
    () => this.api.reports(),
  );
  readonly selectedId = signal<number | undefined>(undefined);
  readonly selected = computed(() =>
    this.list.value()?.reports.find((r) => r.id === this.selectedId()),
  );
  readonly selectedList = computed(() => {
    const r = this.selected();
    return r ? [r] : [];
  });
  readonly view = signal<'preview' | 'history'>('preview');
  readonly runs = loader(
    () => (this.view() === 'history' ? this.selectedId() : undefined),
    (id) => this.api.reportRuns(id),
  );
  readonly editing = signal<Partial<Report> | null>(null);
  readonly editQuery = signal('');
  readonly confirmRun = signal<Report | null>(null);
  readonly confirmDelete = signal<Report | null>(null);
  readonly busy = signal(false);
  readonly running = signal(false);
  readonly formError = signal('');
  readonly pageError = signal('');
  readonly info = signal('');
  readonly pdf = new PdfView(inject(DomSanitizer));
  runDeliver = true;

  readonly templateIds = Object.keys(TEMPLATES);
  readonly periods = PERIODS;
  readonly weekdays = WEEKDAYS;
  readonly hours = Array.from({ length: 24 }, (_, i) => i);
  readonly monthdays = Array.from({ length: 28 }, (_, i) => i + 1);
  readonly newTitle = $localize`:@@reports.newTitle:New report`;
  readonly editTitle = $localize`:@@reports.editTitle:Edit report`;
  readonly scheduledLabel = $localize`:@@reports.trigger.schedule:scheduled`;
  readonly manualLabel = $localize`:@@reports.trigger.manual:run now`;
  readonly allSections = computed(() => this.list.value()?.sections ?? Object.keys(SECTIONS));
  /** Notification channels, for admins (the only ones who edit reports). */
  readonly channels = loader(
    () => (this.auth.isAdmin() ? true : undefined),
    () => this.api.channels(),
  );
  readonly channelList = computed<Channel[]>(() => this.channels.value()?.channels ?? []);
  readonly hasRecipients = computed(() =>
    (this.list.value()?.reports ?? []).some((r) => r.recipients),
  );
  ago = ago;
  dt = dateTime;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.pdf.clear());
  }

  templateLabel = (t: string) => TEMPLATES[t] ?? t;
  sectionLabel = (s: string) => SECTIONS[s] ?? s;
  periodLabel = (p: string) => PERIODS.find((x) => x.id === p)?.label ?? p;
  pad = (n: number) => String(n).padStart(2, '0');
  kb = (n: number) => `${Math.max(1, Math.round(n / 1024))} KB`;
  filterCount = (r: Report) => (r.query ? 1 : 0);
  channelNames = (r: Report) =>
    (r.channels ?? []).flatMap((id) => this.channelList().find((c) => c.id === id)?.name ?? []);
  canDeliver = (r: Report | null) =>
    !!r && ((!!r.recipients && !!this.list.value()?.emailEnabled) || !!r.channels?.length);
  recipientCount = (r: Report) => (r.recipients ? r.recipients.split(',').length : 0);
  fileName = (r: Report) => `${slug(r.name)}-${new Date().toISOString().slice(0, 10)}.pdf`;

  scheduleLabel(r: Report) {
    const at = `${this.pad(r.hour)}:00`;
    const day = WEEKDAYS[r.weekday];
    switch (r.schedule) {
      case 'daily':
        return $localize`:@@reports.when.daily:Daily at ${at}:time:`;
      case 'weekly':
        return $localize`:@@reports.when.weekly:Weekly on ${day}:day: at ${at}:time:`;
      case 'monthly':
        return $localize`:@@reports.when.monthly:Monthly on day ${r.monthday}:day: at ${at}:time:`;
    }
    return $localize`:@@reports.when.off:On demand`;
  }

  select(r: Report | undefined) {
    this.selectedId.set(r?.id);
    this.pdf.clear();
    if (r && this.view() === 'preview') this.pdf.load(() => this.api.previewReport(r));
  }

  setView(v: 'preview' | 'history') {
    this.view.set(v);
    const r = this.selected();
    if (v === 'preview' && r && !this.pdf.url() && !this.pdf.loading())
      this.pdf.load(() => this.api.previewReport(r));
  }

  openEdit(r?: Report, template: Report['template'] = 'summary') {
    const tpl = this.list.value()?.templates ?? {};
    const e = r
      ? { ...r, sections: [...r.sections], channels: [...(r.channels ?? [])] }
      : blank(template, [...(tpl[template] ?? [])]);
    this.editQuery.set(e.query ?? '');
    this.editing.set(e);
    this.formError.set('');
  }

  setTemplate(e: Partial<Report>, t: Report['template']) {
    if (!e.name || Object.values(TEMPLATES).includes(e.name)) e.name = TEMPLATES[t];
    e.template = t;
    e.sections = [...(this.list.value()?.templates[t] ?? [])];
  }

  setPeriod(e: Partial<Report>, p: Report['period']) {
    e.period = p;
    if (e.schedule !== 'off' && SCHEDULE_FOR[p]) e.schedule = SCHEDULE_FOR[p];
  }

  /** Turning a schedule on picks the one that matches a calendar period. */
  setSchedule(e: Partial<Report>, s: Report['schedule']) {
    if (e.schedule === 'off' && s !== 'off') {
      const match = Object.entries(SCHEDULE_FOR).find(([, v]) => v === s)?.[0] as
        Report['period'] | undefined;
      if (match && !SCHEDULE_FOR[e.period!]) e.period = match;
    }
    e.schedule = s;
  }

  toggleChannel(e: Partial<Report>, id: number) {
    const cur = e.channels ?? [];
    e.channels = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
  }

  toggleSection(e: Partial<Report>, s: string) {
    const cur = e.sections ?? [];
    e.sections = cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s];
  }

  async save() {
    const e = this.editing();
    if (!e) return;
    this.busy.set(true);
    this.formError.set('');
    try {
      const saved = await this.api.saveReport({ ...e, query: this.editQuery() });
      this.editing.set(null);
      this.list.reload();
      this.select(saved);
    } catch (err) {
      this.formError.set(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  async run() {
    const r = this.confirmRun();
    this.confirmRun.set(null);
    if (!r) return;
    this.running.set(true);
    this.pageError.set('');
    try {
      const res = await this.api.runReport(r.id, this.runDeliver && this.canDeliver(r));
      if (res.status === 'ok') {
        this.flash(
          res.emailed
            ? $localize`:@@reports.ranEmailed:${r.name}:name: was generated and emailed.`
            : this.runDeliver && r.channels.length
              ? $localize`:@@reports.ranSent:${r.name}:name: was generated and sent to its channels.`
              : $localize`:@@reports.ran:${r.name}:name: was generated; it's in its history.`,
        );
      } else {
        this.pageError.set(res.error ?? '');
      }
      this.list.reload();
      this.runs.reload();
    } catch (err) {
      this.pageError.set(errorMessage(err));
    } finally {
      this.running.set(false);
    }
  }

  async remove() {
    const r = this.confirmDelete();
    this.confirmDelete.set(null);
    if (!r) return;
    try {
      await this.api.deleteReport(r.id);
      this.select(undefined);
      this.list.reload();
    } catch (err) {
      this.pageError.set(errorMessage(err));
    }
  }

  async download(run: ReportRun, r: Report) {
    try {
      saveBlob(
        await this.api.reportRunPdf(run.id),
        `${slug(r.name)}-${new Date(run.from).toISOString().slice(0, 10)}.pdf`,
      );
    } catch (err) {
      this.pageError.set(errorMessage(err));
    }
  }

  private flash(msg: string) {
    this.info.set(msg);
    setTimeout(() => this.info.set(''), 5000);
  }
}

const slug = (s: string) => s.replace(/[^A-Za-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'report';

function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

/** A PDF fetched into a blob: URL for the browser's viewer; the latest load wins. */
class PdfView {
  readonly loading = signal(false);
  readonly error = signal('');
  readonly url = signal('');
  readonly frame = signal<SafeResourceUrl | null>(null);
  private seq = 0;

  constructor(private sanitizer: DomSanitizer) {}

  clear() {
    this.seq++;
    if (this.url()) URL.revokeObjectURL(this.url());
    this.url.set('');
    this.frame.set(null);
    this.loading.set(false);
    this.error.set('');
  }

  async load(fetch: () => Promise<Blob>) {
    this.clear();
    const my = this.seq;
    this.loading.set(true);
    try {
      const blob = await fetch();
      if (my !== this.seq) return;
      const url = URL.createObjectURL(blob);
      this.url.set(url);
      this.frame.set(this.sanitizer.bypassSecurityTrustResourceUrl(url));
    } catch (e) {
      if (my === this.seq) this.error.set(errorMessage(e));
    } finally {
      if (my === this.seq) this.loading.set(false);
    }
  }

  save(name: string) {
    const a = document.createElement('a');
    a.href = this.url();
    a.download = name;
    a.click();
  }
}
