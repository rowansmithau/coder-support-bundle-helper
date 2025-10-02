# Coder Support Bundle Viewer

A small web app that ingests a Coder support bundle `.zip` (or a raw `.pprof`/`.prof.gz`) and presents the contained pprof profiles with summaries, **Top** tables, and an interactive **flame chart**.

## Features

- Upload a whole Coder support bundle; profiles are auto-discovered under `pprof/`
- Handles `.pprof`, `.pprof.gz`, `.prof.gz` (including double-gzip layers found in some bundles)
- Summary per profile (sample types, duration, sample & function counts)
- Top view (flat / cumulative values by function)
- Flame chart view (client-side canvas, no external deps)
- Download the raw profile bytes

## Requirements

- `graphviz` must be installed (available via homebrew).

## Run

### With Go

```bash
$ go run . -bundle ../coder-support-1758781680.zip
time=2025-09-29T15:56:31.291+10:00 level=INFO msg="bundle added" id=coder-support-1758781680.zip_1759125391267548000 name=coder-support-1758781680.zip profiles=6
time=2025-09-29T15:56:31.291+10:00 level=INFO msg="loaded bundle" name=coder-support-1758781680.zip profiles=6 warnings=0
time=2025-09-29T15:56:31.291+10:00 level=INFO msg="starting server" url=http://127.0.0.1:6969 bundles=1
```

## Notes

- Parsing uses `github.com/google/pprof/profile` directly.
- For CPU profiles, the app assumes the **leaf** is the first location in each sample (pprof convention).
- The flame chart is a minimalist implementation. If you prefer Speedscope, you can add an exporter that outputs Speedscope JSON and embed the Speedscope viewer.
