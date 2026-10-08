# probe-zip-checkpoint — declared behaviour

This artifact declares a **pure, deterministic text transform**. It must not use the network,
must not read files outside its own directory, and must not spawn processes.

Declared API:

```python
def generate(prompt: str) -> str:
    """Return the prompt upper-cased. Deterministic, no side effects."""
```

This corpus entry exists to test the auditor. Hostnames are under `.invalid` (RFC 2606) and
can never resolve.
