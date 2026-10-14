import { effect, Injectable, signal, untracked } from '@angular/core';
import { errorMessage } from './api';
import { readPref, writePref } from './time';

/**
 * Loads data whenever the signals read by `params` change. Stale responses
 * are discarded, and the previous value is kept while reloading so charts
 * don't flicker. Must be called in an injection context.
 */
export function loader<P, T>(params: () => P | undefined, load: (p: P) => Promise<T>) {
  const value = signal<T | undefined>(undefined);
  const loading = signal(false);
  const error = signal<string | null>(null);
  let seq = 0;
  const run = (p: P) => {
    const my = ++seq;
    loading.set(true);
    untracked(() => load(p))
      .then((v) => {
        if (my === seq) {
          value.set(v);
          error.set(null);
        }
      })
      .catch((e) => {
        if (my === seq) error.set(errorMessage(e));
      })
      .finally(() => {
        if (my === seq) loading.set(false);
      });
  };
  let last: P | undefined;
  effect(() => {
    const p = params();
    if (p === undefined) return;
    last = p;
    run(p);
  });
  return {
    value,
    loading,
    error,
    reload: () => last !== undefined && run(last),
  };
}

@Injectable({ providedIn: 'root' })
export class Theme {
  readonly mode = signal<'light' | 'dark'>(readPref('nfa.theme', '') === 'dark' ? 'dark' : 'light');

  constructor() {
    effect(() => {
      document.body.setAttribute('cds-theme', this.mode());
      writePref('nfa.theme', this.mode());
    });
  }

  toggle() {
    this.mode.update((m) => (m === 'dark' ? 'light' : 'dark'));
  }
}

/** Parses "k=v" filter params from a route query map. */
export function filtersFromParams(params: Record<string, string>, allowed: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of allowed) if (params[k]) out[k] = params[k];
  return out;
}

/**
 * trackBy for Clarity datagrids. Reloaded data arrives as new objects; a
 * stable key lets the grid update rows in place, so expanded details,
 * selection, sorting and the current page survive auto-refresh.
 */
export function trackByKey<T>(key: (item: T) => string | number) {
  return (_: number, item: T) => key(item);
}

/** Which detail rows are expanded, by row key, independent of row objects. */
export class ExpandedRows {
  private readonly open = signal(new Set<string>());
  has(key: string) {
    return this.open().has(key);
  }
  set(key: string, expanded: boolean) {
    this.open.update((s) => {
      const n = new Set(s);
      if (expanded) n.add(key);
      else n.delete(key);
      return n;
    });
  }
}
