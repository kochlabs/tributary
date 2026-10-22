// Seeds a demo instance with the names an administrator would set, then
// takes the screenshots in docs/screenshots. Run by run.sh.
//
// Environment: BASE (the instance's URL), PASSWORD (admin's), OUT (output
// directory), CHROME (browser executable).
import puppeteer from 'puppeteer-core';

const { BASE, PASSWORD, OUT, CHROME } = process.env;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const EXPORTERS = [
  ['127.0.1.1', 'core-rtr-01', 'Core router', 'HQ · Data center'],
  ['127.0.1.2', 'edge-fw-01', 'Edge firewall', 'HQ · DMZ'],
  ['127.0.1.3', 'dc-sw-01', 'Data center switch', 'HQ · Data center'],
  ['127.0.1.4', 'branch-rtr-01', 'Branch router', 'Denver branch'],
];
const G = 1e9;
const INTERFACES = {
  '127.0.1.1': [[1, 'Te0/0/0', 'Uplink ISP A', 10 * G], [2, 'Te0/0/1', 'Campus core', 10 * G], [3, 'Gi0/1/0', 'Server VLANs', G], [4, 'Gi0/1/1', 'Wireless', G]],
  '127.0.1.2': [[1, 'ethernet1/1', 'Outside', 10 * G], [2, 'ethernet1/2', 'Inside', 10 * G], [5, 'ethernet1/5', 'DMZ', G]],
  '127.0.1.3': [[49, 'Et49', 'Spine uplink', 100 * G], [10, 'Et10', 'Hypervisor 1', 25 * G], [11, 'Et11', 'Hypervisor 2', 25 * G], [12, 'Et12', 'Hypervisor 3', 25 * G], [13, 'Et13', 'Storage', 25 * G]],
  '127.0.1.4': [[1, 'Gi0/0', 'WAN', G], [2, 'Gi0/1', 'LAN', G]],
};
// MAC addresses come from cmd/flowgen's simulated clients.
const DEVICES = [
  ['3c:22:fb:10:00:00', 'Design MacBook Pro'], ['f4:d4:88:10:1e:ef', 'Marketing iMac'], ['00:1e:4f:10:3d:de', 'Finance workstation'],
  ['18:db:f2:10:5c:cd', 'Reception PC'], ['00:50:56:11:16:67', 'Build server VM'], ['b8:27:eb:11:35:56', 'Lobby display'], ['00:11:32:11:54:45', 'Backup NAS'],
];

const browser = await puppeteer.launch({ executablePath: CHROME, args: ['--ignore-certificate-errors', '--no-sandbox'], defaultViewport: { width: 1440, height: 960 } });
const page = await browser.newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(e.message));
page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));

async function api(path, method, body) {
  const status = await page.evaluate(async (path, method, body) => {
    const r = await fetch(path, { method, headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'nfa' }, body: JSON.stringify(body) });
    return r.status;
  }, path, method, body);
  if (status !== 200) throw new Error(`${method} ${path}: ${status}`);
}

// Preferences the app keeps in the browser: the last 24 hours, light theme,
// admin menu groups collapsed, no "change the initial password" banner.
async function prefs(extra = {}) {
  await page.evaluate((extra) => {
    const p = { 'nfa.range': '24h', 'nfa.theme': 'light', 'nfa.navGroups': '{}', 'nfa.dismissedNotices': '["initial-password"]', ...extra };
    for (const [k, v] of Object.entries(p)) localStorage.setItem(k, v);
  }, extra);
}

async function shot(name, url, prepare) {
  await page.goto(BASE + url, { waitUntil: 'networkidle0' });
  await sleep(2500);
  if (prepare) {
    await prepare();
    await sleep(1500);
  }
  await page.mouse.move(1430, 950); // away from anything with a hover state
  await page.screenshot({ path: `${OUT}/${name}.png` });
  console.log(`  ${name}.png`);
}

const expandRow = (n) => () => page.evaluate((n) => document.querySelectorAll('clr-dg-row .datagrid-expandable-caret-button')[n]?.click(), n);
const trafficByService = () =>
  page.evaluate(() => {
    const s = [...document.querySelectorAll('select')].find((x) => [...x.options].some((o) => o.textContent.includes('Service')));
    s.value = [...s.options].find((o) => o.textContent.includes('Service')).value;
    s.dispatchEvent(new Event('change'));
  });

await shot('login', '/login');
await page.type('input[name=username]', 'admin');
await page.type('input[name=password]', PASSWORD);
await Promise.all([page.waitForNavigation(), page.click('button[type=submit]')]);

for (const [addr, name, description, location] of EXPORTERS) await api(`/api/exporters/${addr}`, 'PUT', { name, description, location });
for (const [addr, list] of Object.entries(INTERFACES))
  for (const [idx, name, description, speed] of list) await api(`/api/exporters/${addr}/interfaces/${idx}`, 'PUT', { name, description, speed });
for (const [mac, name] of DEVICES) await api(`/api/devices/${encodeURIComponent(mac)}`, 'PUT', { name });

await prefs();
await shot('dashboard', '/dashboard', trafficByService);
await shot('explorer', '/explorer?groupBy=app');
await shot('paths', '/explorer?view=paths&path=device,app,remote_as&limit=8&direction=download');
await shot('interface-paths', '/explorer?view=paths&path=in_if,out_if&exporter=127.0.1.3');
await shot('flow-search', '/flows?exporter=127.0.1.2', expandRow(10));
await shot('devices', '/devices', expandRow(0));
await shot('exporters', '/exporters');
await shot('exporter-detail', '/exporters/127.0.1.1');
await shot('enrichment', '/admin/enrichment');
await prefs({ 'nfa.theme': 'dark' });
await shot('dashboard-dark', '/dashboard', trafficByService);

await browser.close();
if (errors.length) {
  console.error('browser errors:\n  ' + errors.join('\n  '));
  process.exit(1);
}
