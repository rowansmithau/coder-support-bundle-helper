# Coder Support Bundle Viewer

A small web app that ingests a Coder support bundle `.zip` (or a raw `.pprof`/`.prof.gz`) and presents the contained data:

- pprof profiles with summaries, **Top** tables, and an interactive **flame chart**
- Prometheus metrics (deployment & agent snapshots) rendered inside an embedded Prometheus + Grafana stack
- Bundle metadata such as license status, health snapshots, and more

## Features

- Upload an entire support bundle; profiles and Prometheus snapshots are auto-discovered
- Handles `.pprof`, `.pprof.gz`, `.prof.gz` (including double-gzip layers found in some bundles)
- Summary per profile (sample types, duration, sample & function counts)
- Top view (flat / cumulative values by function)
- Flame chart view (client-side canvas, no external deps)
- Download the raw profile bytes
- Automatically spins up Prometheus backed by the bundle snapshots and Grafana preloaded with the upstream Coder dashboards
- Prometheus/Grafana buttons deep-link to the relevant time range for the snapshots (no manual range tweaking required)
- Prometheus samples are tagged with `bundle_id`, `snapshot_source`, and `snapshot_name` so deployment vs. agent data is easy to differentiate

## Requirements

- `graphviz` installed (e.g. `brew install graphviz`)
- `prometheus` binary on `PATH` (e.g. `brew install prometheus`)
- `grafana` binary on `PATH` (e.g. `brew install grafana`)
- `brew install graphviz prometheus grafana`

## Run

### With Go

```bash
$ go run . -bundle ./support-bundle.zip
time=2025-09-29T15:56:31.291+10:00 level=INFO msg="bundle added" id=support-bundle.zip_1759125391267548000 name=support-bundle.zip profiles=6
time=2025-09-29T15:56:31.291+10:00 level=INFO msg="loaded bundle" name=support-bundle.zip profiles=6 warnings=0
time=2025-09-29T15:56:31.291+10:00 level=INFO msg="starting server" url=http://127.0.0.1:6969 bundles=1
time=2025-09-29T15:56:31.472+10:00 level=INFO msg="grafana started" url=http://127.0.0.1:53208 prometheus=http://127.0.0.1:53207
time=2025-09-29T15:56:31.472+10:00 level=INFO msg="prometheus auto-started" bundle=support-bundle.zip_1759125391267548000 url=http://127.0.0.1:53207
```

Then open http://127.0.0.1:6969 in your browser.
