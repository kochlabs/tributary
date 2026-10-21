# Development

Requires Go 1.27+ and Node 24+. `make` lists all targets.

```bash
make deb          # build dist/tributary_<version>_amd64.deb
make deploy       # build the package and install it on this machine
make check        # gofmt, vet, tests, web build; run before committing
make dev          # backend on https://localhost:8443 (admin / admin12345)
make serve        # UI with hot reload on :4200, proxying /api
make demo-start   # simulated exporters on 127.0.1.1–4 (make demo-stop)
bin/flowgen -backfill 72h -geoip-dir /var/lib/nfa/geoip   # simulated history
```

Other targets: `make i18n` extracts UI text for translation
([TRANSLATING.md](TRANSLATING.md)), `make notices` regenerates
`THIRD_PARTY_NOTICES.md`, `make fuzz` and `make bench` exercise the decoders.

Tests that need a live service run only when their variable is set:
`NFA_TEST_CH_PW` (ClickHouse), `NFA_TEST_LDAP`, `NFA_TEST_SNMP`,
`NFA_TEST_SMB`.

## Releasing

CI runs `make check` on every push and pull request. Pushing a version tag
publishes a release with the `.deb`, `install.sh`, `SHA256SUMS` and build
attestations:

```bash
git tag -a v0.2.0 -m "Tributary 0.2.0"   # v0.2.0-rc.1 for a pre-release
git push origin v0.2.0
```

Package versions follow tags: a clean checkout of `v0.2.0` builds as `0.2.0`,
later commits as `0.2.0+git<count>.<sha>`, so apt sees each build as newer.
