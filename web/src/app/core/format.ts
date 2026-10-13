import { Metric } from './api';

const SI = ['', 'K', 'M', 'G', 'T', 'P'];

export function si(v: number, digits = 1): string {
  if (!isFinite(v)) return '–';
  let i = 0;
  let x = Math.abs(v);
  while (x >= 1000 && i < SI.length - 1) {
    x /= 1000;
    i++;
  }
  const s = x >= 100 || i === 0 ? x.toFixed(i === 0 && x < 10 && x % 1 ? digits : 0) : x.toFixed(digits);
  return (v < 0 ? '-' : '') + s + (SI[i] ? ' ' + SI[i] : '');
}

export function bits(v: number) {
  return si(v) + (si(v).match(/[KMGTP]$/) ? 'bps' : ' bps');
}

export function bytes(v: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  let x = v;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i++;
  }
  return `${x >= 100 || i === 0 ? x.toFixed(0) : x.toFixed(1)} ${units[i]}`;
}

export function count(v: number): string {
  return si(v).replace(/ /, '');
}

export function rate(v: number, m: Metric): string {
  switch (m) {
    case 'pps':
      return si(v) + (si(v).match(/[KMGTP]$/) ? 'pps' : ' pps');
    case 'fps':
      return si(v) + (si(v).match(/[KMGTP]$/) ? ' flows/s' : ' flows/s');
    default:
      return bits(v);
  }
}

export const METRICS: { id: Metric; label: string }[] = [
  { id: 'bps', label: 'Bits/s' },
  { id: 'pps', label: 'Packets/s' },
  { id: 'fps', label: 'Flows/s' },
];

export function dateTime(ms: number): string {
  if (!ms) return '–';
  return new Date(ms).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function ago(ms: number): string {
  if (!ms) return 'never';
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function duration(sec: number): string {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m ${Math.floor(sec % 60)}s`;
}

const PROTOS: Record<number, string> = {
  1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 103: 'PIM', 112: 'VRRP', 132: 'SCTP',
};

export function proto(p: number): string {
  return PROTOS[p] ?? `IP/${p}`;
}

export function tcpFlags(f: number): string {
  if (!f) return '';
  return ['F', 'S', 'R', 'P', 'A', 'U', 'E', 'C'].filter((_, i) => f & (1 << i)).join('');
}

export const FLOW_TYPES = ['Unknown', 'NetFlow v5', 'NetFlow v9', 'IPFIX', 'sFlow v5'];

export const DIMENSIONS: { id: string; label: string }[] = [
  { id: 'remote_as', label: 'Service (remote organization)' },
  { id: 'local_host', label: 'Device (local host)' },
  { id: 'remote_host', label: 'Remote host' },
  { id: 'remote_country', label: 'Remote country' },
  { id: 'direction', label: 'Direction' },
  { id: 'app', label: 'Application' },
  { id: 'src_addr', label: 'Source address' },
  { id: 'dst_addr', label: 'Destination address' },
  { id: 'host', label: 'Host (either side)' },
  { id: 'conversation', label: 'Conversation' },
  { id: 'proto', label: 'Protocol' },
  { id: 'dst_port', label: 'Destination port' },
  { id: 'src_port', label: 'Source port' },
  { id: 'country', label: 'Country (either side)' },
  { id: 'src_country', label: 'Source country' },
  { id: 'dst_country', label: 'Destination country' },
  { id: 'src_as', label: 'Source AS' },
  { id: 'dst_as', label: 'Destination AS' },
  { id: 'exporter', label: 'Exporter' },
  { id: 'in_if', label: 'Input interface' },
  { id: 'out_if', label: 'Output interface' },
  { id: 'dscp', label: 'DSCP' },
  { id: 'etype', label: 'IP version' },
  { id: 'vlan', label: 'VLAN' },
  { id: 'flow_type', label: 'Flow protocol' },
];

export function dimLabel(id: string) {
  return DIMENSIONS.find((d) => d.id === id)?.label ?? id;
}

/** Filter key to apply when drilling into a row of the given dimension. */
export function drillFilter(dim: string, key: string): Record<string, string> | null {
  switch (dim) {
    case 'src_addr':
      return { src: key };
    case 'dst_addr':
      return { dst: key };
    case 'host':
    case 'local_host':
    case 'remote_host':
      return { host: key };
    case 'remote_as':
      return key && key !== '0' ? { as: key } : null;
    case 'remote_country':
      return key ? { country: key } : null;
    case 'direction':
      return { direction: key };
    case 'conversation': {
      // Local endpoint first: filter on it and narrow to the remote as source or destination.
      const [a, b] = key.split(' ⇄ ');
      return a && b ? { host: a, peer: b } : null;
    }
    case 'app':
      return { app: key };
    case 'proto':
      return { proto: key };
    case 'src_port':
    case 'dst_port':
    case 'src_as':
    case 'dst_as':
    case 'vlan':
    case 'dscp':
    case 'flow_type':
    case 'exporter':
      return { [dim]: key };
    case 'country':
    case 'src_country':
    case 'dst_country':
      return key ? { [dim]: key } : null;
    case 'etype':
      return { etype: key === '34525' ? 'ipv6' : 'ipv4' };
    case 'in_if':
    case 'out_if': {
      const [exp, idx] = key.split('|');
      return { exporter: exp, [dim]: idx };
    }
  }
  return null;
}

export const FILTER_FIELDS: { id: string; label: string; hint: string }[] = [
  { id: 'host', label: 'Host', hint: '10.0.0.5 or 10.0.0.0/8' },
  { id: 'direction', label: 'Direction', hint: 'download, upload, internal or transit' },
  { id: 'peer', label: 'Peer (either side)', hint: 'second host, e.g. with Host for one conversation' },
  { id: 'src', label: 'Source address', hint: 'IP or CIDR' },
  { id: 'dst', label: 'Destination address', hint: 'IP or CIDR' },
  { id: 'port', label: 'Port (either)', hint: '443 or 8000-8100' },
  { id: 'src_port', label: 'Source port', hint: '53' },
  { id: 'dst_port', label: 'Destination port', hint: '443' },
  { id: 'proto', label: 'Protocol', hint: 'tcp, udp, icmp or number' },
  { id: 'app', label: 'Application', hint: 'tcp/443' },
  { id: 'exporter', label: 'Exporter', hint: 'exporter IP' },
  { id: 'iface', label: 'Interface (either)', hint: 'ifIndex' },
  { id: 'in_if', label: 'Input interface', hint: 'ifIndex' },
  { id: 'out_if', label: 'Output interface', hint: 'ifIndex' },
  { id: 'country', label: 'Country (either)', hint: 'US or US,DE' },
  { id: 'src_country', label: 'Source country', hint: 'ISO code, e.g. CN' },
  { id: 'dst_country', label: 'Destination country', hint: 'ISO code, e.g. US' },
  { id: 'as', label: 'AS (either)', hint: '15169' },
  { id: 'src_as', label: 'Source AS', hint: '15169' },
  { id: 'dst_as', label: 'Destination AS', hint: '15169' },
  { id: 'vlan', label: 'VLAN', hint: '100' },
  { id: 'dscp', label: 'DSCP', hint: '46' },
  { id: 'etype', label: 'IP version', hint: 'ipv4 or ipv6' },
  { id: 'nexthop', label: 'Next hop', hint: 'IP or CIDR' },
];

export function filterLabel(id: string) {
  return FILTER_FIELDS.find((f) => f.id === id)?.label ?? id;
}

const SERVICES: Record<number, string> = {
  20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP', 88: 'Kerberos',
  110: 'POP3', 123: 'NTP', 135: 'MS-RPC', 137: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap', 179: 'BGP', 389: 'LDAP',
  443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 500: 'IKE', 514: 'Syslog', 587: 'Submission', 636: 'LDAPS', 853: 'DoT', 993: 'IMAPS', 995: 'POP3S',
  1194: 'OpenVPN', 1433: 'MSSQL', 1521: 'Oracle', 1812: 'RADIUS', 1883: 'MQTT', 2049: 'NFS', 3306: 'MySQL', 3389: 'RDP', 3478: 'STUN',
  4500: 'IPsec', 4789: 'VXLAN', 5060: 'SIP', 5061: 'SIPS', 5353: 'mDNS', 5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 6379: 'Redis',
  6443: 'K8s API', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 9092: 'Kafka', 9200: 'Elastic', 27017: 'MongoDB', 51820: 'WireGuard',
};

/** The application port of a flow: the well-known side, else the lower port. */
export function appPort(srcPort: number, dstPort: number): number {
  if (dstPort < 1024) return dstPort;
  if (srcPort < 1024) return srcPort;
  if (SERVICES[dstPort]) return dstPort;
  if (SERVICES[srcPort]) return srcPort;
  return Math.min(srcPort, dstPort);
}

export function serviceName(port: number): string {
  return SERVICES[port] ?? '';
}

export function samplingLabel(override: number, live?: { sampling: number; samplingSource: string } | null): { rate: string; source: string; hint: string } {
  if (override) return { rate: `1:${override}`, source: 'override', hint: 'Manual override set on this exporter' };
  if (!live) return { rate: '–', source: '', hint: '' };
  const hints: Record<string, string> = {
    announced: 'Announced by the device in its options data',
    remembered: 'Remembered from before the last restart; waiting for the device to confirm',
    packet: 'Carried in every datagram (sFlow / NetFlow v5)',
    unsampled: 'Device reports no sampling: every flow is exported',
  };
  return { rate: live.samplingSource === 'unsampled' ? '1:1' : `1:${live.sampling}`, source: live.samplingSource, hint: hints[live.samplingSource] ?? '' };
}

export function shortTime(ms: number): string {
  const d = new Date(ms);
  const sameDay = new Date().toDateString() === d.toDateString();
  const t = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  return sameDay ? t : `${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} ${t}`;
}
