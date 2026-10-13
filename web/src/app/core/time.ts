import { computed, effect, Injectable, signal } from '@angular/core';
import { TimeQuery } from './api';

export interface Preset {
  id: string;
  label: string;
  ms: number;
}

export const PRESETS: Preset[] = [
  { id: '15m', label: 'Last 15 minutes', ms: 15 * 60e3 },
  { id: '1h', label: 'Last hour', ms: 3600e3 },
  { id: '6h', label: 'Last 6 hours', ms: 6 * 3600e3 },
  { id: '24h', label: 'Last 24 hours', ms: 24 * 3600e3 },
  { id: '7d', label: 'Last 7 days', ms: 7 * 86400e3 },
  { id: '30d', label: 'Last 30 days', ms: 30 * 86400e3 },
];

/** Global time range shared by every analytics page. */
@Injectable({ providedIn: 'root' })
export class TimeRange {
  readonly preset = signal<string>(readPref('nfa.range', '1h'));
  readonly custom = signal<TimeQuery | null>(null);
  readonly autoRefresh = signal<boolean>(readPref('nfa.autoRefresh', 'true') === 'true');
  /** Bumped to ask the header picker to open its custom range dialog. */
  readonly customRequest = signal(0);
  /** Bumped to force all pages to reload. */
  readonly tick = signal(0);

  readonly label = computed(() => {
    const c = this.custom();
    if (c) return `${fmt(c.from)} – ${fmt(c.to)}`;
    return PRESETS.find((p) => p.id === this.preset())?.label ?? this.preset();
  });

  /** The concrete window; re-evaluated whenever tick changes. */
  readonly window = computed<TimeQuery>(() => {
    this.tick();
    const c = this.custom();
    if (c) return c;
    const ms = PRESETS.find((p) => p.id === this.preset())?.ms ?? 3600e3;
    const to = Date.now();
    return { from: to - ms, to };
  });

  constructor() {
    effect(() => writePref('nfa.range', this.preset()));
    effect(() => writePref('nfa.autoRefresh', String(this.autoRefresh())));
    setInterval(() => {
      if (this.autoRefresh() && !this.custom() && document.visibilityState === 'visible') this.refresh();
    }, 60_000);
  }

  setPreset(id: string) {
    this.custom.set(null);
    this.preset.set(id);
    this.refresh();
  }

  setCustom(from: number, to: number) {
    this.custom.set({ from, to });
    this.refresh();
  }

  refresh() {
    this.tick.update((t) => t + 1);
  }
}

function fmt(ms: number) {
  return new Date(ms).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export function readPref(key: string, def: string): string {
  try {
    return localStorage.getItem(key) ?? def;
  } catch {
    return def;
  }
}

export function writePref(key: string, v: string) {
  try {
    localStorage.setItem(key, v);
  } catch {
    /* storage unavailable */
  }
}
