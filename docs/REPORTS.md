# Reports

PDF reports generated on the appliance, on demand or on a schedule, and
optionally emailed. **Reports** lists them; administrators create and edit
them, everyone can preview them and download past runs.

## A report

- **Template:** Network summary or Security digest. A template only sets the
  default sections; any section can be added or removed:
  headline figures, traffic over time, top services, devices, applications,
  remote countries, threat feed matches, exposed services, new devices and
  exporters.
- **Period:** yesterday, last week (Monday to Sunday) or last month, in the
  appliance's time zone; or the last 24 hours, 7 days or 30 days.
- **Filters:** optional, as in the Traffic Explorer, e.g. one exporter.
- **Schedule:** off, daily, weekly or monthly at a set hour. Pair a calendar
  period with its schedule (yesterday daily, last week weekly) to cover each
  period once.
- **Email to:** recipients of scheduled runs, as a PDF attachment. Needs
  **Configuration → Email**.
- **Keep:** how many runs stay on the appliance (in `/var/lib/nfa/reports`).

**Run now** makes a run immediately, optionally emailed. **Preview** renders
the period as of now without keeping or sending anything. A failed scheduled
run shows in the report's history and raises a notice.

## Sections worth knowing

- **Exposed services:** local hosts that answered connections from the
  internet, by port and number of remote hosts. It counts replies (TCP
  SYN+ACK), so scans of closed ports don't show; without TCP flags from the
  exporter, any reply counts.
- **New devices:** devices first seen in the period.
- **Threat feed matches:** see [THREAT-FEEDS.md](THREAT-FEEDS.md).

Report text is in English. Names in scripts the embedded font doesn't cover
(Chinese, Japanese, Korean) don't render.
