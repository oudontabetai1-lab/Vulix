## Summary of Changes

A concise technical explanation of the changes introduced in this pull request.

## Motivation & Context

Why is this change required? What problem does it solve?
Fixes #(issue number)

## Type of Change

- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality or scanner detection)
- [ ] Refactor / Code cleanliness (no functional change)
- [ ] Documentation update
- [ ] Other (please describe):

## Scanner & Test Verification

- [ ] If this PR introduces or modifies scanner detection logic, pure functions are used and browser-independent tests are included.
- [ ] Twin fixtures (vulnerable + safe test cases) are added where applicable to prevent false positives.
- [ ] All automated tests pass locally: `pytest -q --ignore=tests/test_end_to_end_scan.py`
- [ ] No regression introduced to existing scanners.

## Testing Details

Describe how you tested these changes (e.g. command executed, test files run, sample target output):
```bash
pytest -q --ignore=tests/test_end_to_end_scan.py
```

## Checklist

- [ ] My code adheres to the existing coding style of this project.
- [ ] I have added tests that prove my fix is effective or that my feature works.
- [ ] New and existing unit tests pass locally with my changes.
- [ ] I have commented my code, particularly in hard-to-understand areas.
