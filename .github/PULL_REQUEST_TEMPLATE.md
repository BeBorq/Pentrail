## What this changes

## How it was tested
- [ ] `gofmt -l .` prints nothing
- [ ] `go vet ./...` and `go vet -tags sqlcipher ./...`
- [ ] `CGO_ENABLED=1 go test -count=1 ./...`
- [ ] `CGO_ENABLED=1 go test -tags sqlcipher -count=1 ./...`
- [ ] Platforms tested natively: Linux / Windows (say which)
- [ ] A regression test fails without this change

## Checklist
- [ ] Nothing is reported as captured, complete or saved unless it was
- [ ] Masking is not weakened; new rules have tests
- [ ] The viewer still never changes captured evidence
- [ ] Tests, fixtures and screenshots use synthetic data only
- [ ] No databases, backups, reports, logs or build output are committed
- [ ] Documentation in `docs/` is updated if behaviour or a limit changed
