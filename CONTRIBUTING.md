# Contributing to Vulix

Thank you for your interest in contributing to Vulix! We welcome bug reports, feature requests, documentation improvements, and code contributions from the community.

---

## Code of Conduct & Expectations

We strive to create an open, welcoming, and productive environment. Please treat all contributors with respect, focus on constructive feedback, and collaborate in good faith.

---

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Git

### Setup Steps

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/vulix.git
   cd vulix
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   playwright install chromium
   ```

---

## Running Tests

All changes must pass existing and new automated tests.

- **Fast test suite (unit and scanner tests, excluding live E2E scans):**
  ```bash
  pytest -q --ignore=tests/test_end_to_end_scan.py
  ```

- **End-to-End (E2E) integration tests (opt-in):**
  Full live browser/network integration tests require setting `WSCAN_E2E=1`:
  ```bash
  WSCAN_E2E=1 pytest tests/test_end_to_end_scan.py
  ```

Ensure all non-E2E tests pass cleanly before submitting your pull request.

---

## Contribution Guidelines & PR Requirements

To keep the codebase maintainable and stable, we ask that you follow these guidelines:

1. **Keep Pull Requests Focused:**
   - Address a single issue, feature, or bug per PR.
   - Avoid combining large refactors with new features or bug fixes.

2. **Tests are Required:**
   - Every bug fix should include a regression test that fails without the fix and passes with it.
   - Every new feature or scanner rule must include corresponding unit tests.

3. **Writing Scanners and Fixtures:**
   - **Pure Detection Logic:** Separate detection rules and parsing logic into pure, browser-independent functions where possible. This allows detection rules to be tested quickly with mock inputs without launching Playwright or Chromium.
   - **Vulnerable + Safe Twin Fixtures:** When introducing a new detector or vulnerability rule, provide paired test cases:
     - A positive fixture (vulnerable case) that triggers the detector.
     - A negative fixture (safe case) that ensures the detector does not produce false positives.

4. **Verify Locally Before Submitting:**
   - Run `pytest -q --ignore=tests/test_end_to_end_scan.py` and verify all tests pass (green).
   - Ensure code is cleanly formatted and free of extraneous debug logs.

---

## Submitting a Pull Request

1. **Create a descriptive topic branch:**
   ```bash
   git checkout -b feature/my-new-detector
   # or
   git checkout -b fix/issue-description
   ```

2. **Commit your changes:**
   - Write clear, concise commit messages explaining the rationale behind the change.

3. **Push to your fork:**
   ```bash
   git push origin feature/my-new-detector
   ```

4. **Open a Pull Request:**
   - Use the provided PR template.
   - Provide a concise technical summary of what was changed and why.
   - Reference any relevant GitHub issues (e.g., `Fixes #123`).
   - Document how the change was tested and confirm that test suites pass.
