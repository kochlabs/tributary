import { DeviceInfo } from './api';

// Finding devices on the Devices page: a name, an address or a MAC in any
// notation, typed into one box.

/** A MAC's hex digits, lower case: aa:bb…, AA-BB…, aabb.ccdd… and aabbcc… alike. */
export function macDigits(s: string): string {
  return s.toLowerCase().replace(/[^0-9a-f]/g, '');
}

/**
 * The hex digits a search word stands for when it is (part of) a MAC: four
 * to twelve bare hex digits (a851, a851abc0), colon or dash pairs (aa:bb:cc,
 * dd-ee-ff) or Cisco dotted groups (aabb.ccdd.eeff, aabb.cc). Null otherwise.
 * A hex-looking word ("cafe") is still matched as text too.
 */
export function macTerm(word: string): string | null {
  const w = word.toLowerCase();
  if (/^[0-9a-f]{4,12}$/.test(w)) return w; // bare hex, whole or part: a851abc0
  if (/^[0-9a-f]{1,2}([:-][0-9a-f]{1,2})+[:-]?$/.test(w)) return macDigits(w);
  if (/^[0-9a-f]{4}(\.[0-9a-f]{1,4})+\.?$/.test(w)) return macDigits(w);
  return null;
}

const FULL_IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Words of a search, lower case. */
export function searchWords(text: string): string[] {
  return text.toLowerCase().split(/\s+/).filter(Boolean);
}

/** Everything a device can be found by, lower case. */
function haystack(d: DeviceInfo): string {
  const inv = d.inventory;
  return [
    d.name,
    d.customName,
    d.vendor,
    d.mac,
    ...d.ipv4,
    ...d.ipv6,
    ...(d.ips ?? []).map((i) => i.ip),
    inv?.name,
    inv?.role,
    inv?.site,
    ...(inv?.tags ?? []),
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

/**
 * Whether a device matches every word: a MAC (part) by its digits, a whole
 * IPv4 address exactly, anything else as text anywhere in its name, vendor,
 * addresses or inventory record.
 */
export function deviceMatches(d: DeviceInfo, words: string[]): boolean {
  if (!words.length) return true;
  const text = haystack(d);
  const mac = macDigits(d.mac);
  const addrs = [...d.ipv4, ...(d.ips ?? []).map((i) => i.ip)];
  return words.every((w) => {
    if (FULL_IPV4.test(w)) return addrs.includes(w);
    const m = macTerm(w);
    if (m && mac.includes(m)) return true;
    return text.includes(w);
  });
}
