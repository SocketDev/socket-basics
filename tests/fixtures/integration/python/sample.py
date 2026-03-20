"""Minimal clean Python fixture for socket-basics integration tests.

This file is intentionally free of vulnerabilities so that a socket-basics
scan exits 0 (no findings). Its only purpose is to give the scanner a real
Python file to process, confirming the full parse → rule-match → report
pipeline completes without errors.
"""


def greet(name: str) -> str:
    """Return a formatted greeting string."""
    return f"Hello, {name}!"


def add(a: int, b: int) -> int:
    """Return the sum of two integers."""
    return a + b


if __name__ == "__main__":
    print(greet("World"))
    print(add(1, 2))
