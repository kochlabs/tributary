/** Minimal IPv4/IPv6 parsing and prefix matching for form validation hints. */

function parseIP(s: string): { v6: boolean; n: bigint } | null {
  s = s.trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    const p = s.split('.').map(Number);
    if (p.some((x) => x > 255)) return null;
    return { v6: false, n: p.reduce((a, x) => (a << 8n) | BigInt(x), 0n) };
  }
  if (!s.includes(':')) return null;
  const v4tail = s.match(/(\d{1,3}(\.\d{1,3}){3})$/);
  if (v4tail) {
    const v4 = parseIP(v4tail[1]);
    if (!v4) return null;
    s = s.slice(0, -v4tail[1].length) + ((v4.n >> 16n) & 0xffffn).toString(16) + ':' + (v4.n & 0xffffn).toString(16);
  }
  const [head, tail, extra] = s.split('::');
  if (extra !== undefined) return null;
  const hp = head ? head.split(':') : [];
  const tp = tail !== undefined && tail ? tail.split(':') : [];
  const missing = 8 - hp.length - tp.length;
  if ((tail === undefined && missing !== 0) || missing < 0) return null;
  const groups = [...hp, ...Array(tail === undefined ? 0 : missing).fill('0'), ...tp];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  return { v6: true, n: groups.reduce((a, g) => (a << 16n) | BigInt(parseInt(g, 16)), 0n) };
}

/** Whether entry (an address or CIDR prefix) is valid. */
export function validAddrOrPrefix(entry: string): boolean {
  const [a, bits] = entry.trim().split('/');
  const ip = parseIP(a);
  if (!ip) return false;
  if (bits === undefined) return true;
  const b = Number(bits);
  return Number.isInteger(b) && b >= 0 && b <= (ip.v6 ? 128 : 32);
}

/** Whether addr falls inside entry (an address or CIDR prefix). */
export function prefixContains(entry: string, addr: string): boolean {
  const [a, bits] = entry.trim().split('/');
  const p = parseIP(a);
  const x = parseIP(addr);
  if (!p || !x || p.v6 !== x.v6) return false;
  const width = p.v6 ? 128 : 32;
  const len = bits === undefined ? width : Number(bits);
  const shift = BigInt(width - len);
  return p.n >> shift === x.n >> shift;
}

/** Whether s is an IP address, optionally with a port (1.2.3.4:53, [2001:db8::1]:53). */
export function validAddrPort(s: string): boolean {
  s = s.trim();
  const port = (p: string) => /^\d{1,5}$/.test(p) && +p > 0 && +p < 65536;
  const v6 = s.match(/^\[([^\]]+)\]:(\d+)$/);
  if (v6) return parseIP(v6[1])?.v6 === true && port(v6[2]);
  const v4 = s.match(/^([\d.]+):(\d+)$/);
  if (v4) return parseIP(v4[1])?.v6 === false && port(v4[2]);
  return parseIP(s) !== null;
}
