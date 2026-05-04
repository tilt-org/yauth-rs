# scripts/

Vendored copies of yauth-go's OpenAPI conformance tooling. yauth-go is the
canonical home (`yauth-go/scripts/openapi-{diff,conformance}.py`); these
copies exist so this repo's CI can run the gate without a network round
trip to yauth-go on every build.

## Files

- **`openapi-diff.py`** — diagnostic tool. Reports BREAKING / MISSING /
  SHAPE / GO-EXTRA divergences. Exits non-zero only on BREAKING / MISSING.
- **`openapi-conformance.py`** — strict CI gate. Fails on any of the four
  categories. Run by `.github/workflows/ci.yml`'s `openapi-conformance`
  job.

## Keeping in sync

When the canonical scripts in yauth-go change, copy them over:

```bash
cp ../yauth-go/scripts/openapi-{diff,conformance}.py scripts/
```

Then run the gate locally to confirm everything still passes:

```bash
python3 scripts/openapi-conformance.py openapi.json ../yauth-go/openapi.json
```
