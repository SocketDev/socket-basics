# Unit Tests

This directory contains **unit and integration tests** for Socket Basics using pytest.

## Quick Start

```bash
# Setup (first time only)
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=socket_basics
```

## Test Structure

```
tests/
├── test_github_helpers.py    # Helper functions for GitHub PR comments
└── ...                        # Other unit tests
```

## Writing Tests

### Test File Naming
- Test files: `test_*.py`
- Test functions: `test_*`
- Test classes: `Test*`

### Example Test

```python
import pytest
from socket_basics.module import function_to_test

def test_basic_functionality():
    """Test basic functionality with valid input."""
    result = function_to_test("input")
    assert result == "expected_output"

def test_edge_case():
    """Test edge case handling."""
    result = function_to_test("")
    assert result == ""

def test_error_handling():
    """Test error handling."""
    with pytest.raises(ValueError):
        function_to_test(None)
```

### Test Classes

Use test classes to group related tests:

```python
class TestGitHubHelpers:
    """Tests for GitHub helper functions."""

    def test_url_building(self):
        url = build_github_file_url("owner/repo", "abc123", "file.py", 10)
        assert "github.com" in url

    def test_language_detection(self):
        lang = detect_language_from_filename("app.js")
        assert lang == "javascript"
```

## Running Tests

### Run All Tests
```bash
pytest
```

### Run Specific Test File
```bash
pytest tests/test_github_helpers.py
```

### Run Specific Test Function
```bash
pytest tests/test_github_helpers.py::test_detect_language_from_filename
```

### Run Specific Test Class
```bash
pytest tests/test_github_helpers.py::TestDetectLanguageFromFilename
```

### Run with Verbose Output
```bash
pytest -v
```

### Run with Coverage Report
```bash
# Terminal coverage report
pytest --cov=socket_basics tests/

# HTML coverage report
pytest --cov=socket_basics --cov-report=html tests/
open htmlcov/index.html
```

### Run with Markers (Future Enhancement)
```bash
# Run only fast tests
pytest -m "not slow"

# Run only integration tests
pytest -m integration
```

## Test Categories

### Unit Tests
**Purpose:** Test individual functions in isolation
**Speed:** Fast (milliseconds)
**Dependencies:** None (use mocks)
**Location:** `tests/test_*.py`

**Example:**
```python
def test_detect_language_from_filename():
    assert detect_language_from_filename('app.js') == 'javascript'
    assert detect_language_from_filename('main.py') == 'python'
```

### Integration Tests (Future)
**Purpose:** Test multiple components together
**Speed:** Moderate (seconds)
**Dependencies:** Real configs, but mocked external APIs
**Location:** `tests/integration/test_*.py`

**Example:**
```python
def test_formatter_with_config():
    config = create_test_config()
    result = format_notifications(components, config)
    assert len(result) > 0
```

## Mocking External Dependencies

Use pytest fixtures for common test data:

```python
@pytest.fixture
def mock_config():
    """Provide a mock configuration object."""
    return {
        'repo': 'owner/repo',
        'commit_hash': 'abc123',
        'pr_comment_links_enabled': True
    }

def test_with_config(mock_config):
    result = format_with_config(mock_config)
    assert result is not None
```

## Testing Best Practices

### ✅ DO:
- Keep tests fast and isolated
- Test one thing per test function
- Use descriptive test names
- Test both success and error cases
- Use fixtures for common test data
- Run tests before committing

### ❌ DON'T:
- Make external API calls (mock them)
- Depend on test execution order
- Use hardcoded paths (use fixtures)
- Test implementation details
- Skip error case testing

## Continuous Integration

Tests run automatically on:
- Every pull request
- Every commit to main branch
- Before releases

**GitHub Actions Example:**
```yaml
- name: Run Tests
  run: |
    pip install -e ".[dev]"
    pytest --cov=socket_basics tests/
```

## Debugging Tests

### Run Single Test with Debug Output
```bash
pytest tests/test_github_helpers.py::test_name -vv -s
```

### Drop into debugger on failure
```bash
pytest --pdb
```

### Print statements in tests
```python
def test_example():
    result = function()
    print(f"Debug: result = {result}")  # Use -s flag to see output
    assert result == expected
```

## Coverage Goals

- **Target:** 80%+ code coverage for new features
- **Critical paths:** 100% coverage (authentication, security logic)
- **Helper functions:** 90%+ coverage

Check coverage:
```bash
pytest --cov=socket_basics --cov-report=term-missing
```

## Related Testing

For **end-to-end testing** with real vulnerable applications, see:
- `../app_tests/` - Deliberately vulnerable apps for scanner validation
- `../app_tests/README.md` - E2E testing documentation (if it exists)

## Test Data

Test fixtures and sample data should be:
- **Small** - Minimal data needed for the test
- **Realistic** - Representative of actual usage
- **Self-contained** - No external dependencies

**Example:**
```python
SAMPLE_TRACE = """owasp-goat - server.js 72:12-75:6
  -> express routes/auth.js 45:2"""

def test_trace_parsing():
    result = parse_trace(SAMPLE_TRACE)
    assert len(result) == 2
```

## Questions?

- See main [README.md](../README.md) for project overview
- See [docs/](../docs/) for detailed documentation
- Check existing tests for examples
