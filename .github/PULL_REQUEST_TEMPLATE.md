## Summary

<!-- What does this PR change, in one or two sentences? -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Tests / CI
- [ ] Packaging / build

## Checklist

- [ ] I have read CONTRIBUTING.md.
- [ ] `pytest` passes locally (or CI explains why not).
- [ ] `ruff check src tests conftest.py` passes.
- [ ] New protocol behavior is covered by tests with synthetic fixtures
      (no real captured traffic, credentials, or personal data).
- [ ] Documentation updated when user-facing behavior changed.
- [ ] The change preserves the intended-use boundary: STUNScope analyzes
      traffic on owned/authorized networks only.

## Notes for reviewers

<!-- Anything tricky about the decode, threading, or Qt wiring? -->
