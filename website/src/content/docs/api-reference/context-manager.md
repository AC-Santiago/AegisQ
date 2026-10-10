---
title: Context Manager
description: AegisCipher as a context manager — proactive zeroization of any Python-side session buffers on exit.
sidebar:
  badge:
    text: v1.4.0
    variant: tip
---

[`AegisCipher`](/api-reference/aegiscipher/) implements the Python **context manager protocol** (`__enter__` / `__exit__`). On exit, mutable buffers registered with its private hook are **overwritten with zeros in place**, the list is cleared, and the cipher is marked inactive.

The current public methods do not register buffers with this hook. One-shot shared-secret cleanup is performed explicitly in Rust, independently of `with`; it is not implemented with a `Zeroizing` wrapper in `hybrid.rs`. Streaming generators retain native state while iterating.

:::caution[Not a secret-erasure boundary]
Leaving the block does not erase a generated `KeyPair`, caller-owned `secret_key` bytes, plaintext, or a suspended streaming generator. It does not close the cipher or prevent later calls. See [Security Model](/internals/security-model/) for cleanup limitations.
:::

## Basic Usage

```python
from aegisq import AegisCipher

with AegisCipher() as cipher:
    keypair = cipher.generate_keypair()
    package = cipher.encrypt(b"hello", keypair.public_key)
    plaintext = cipher.decrypt(package, keypair.secret_key)
# On exit, __exit__ runs and zeroes any registered buffer (none today).
# Exceptions inside the block still propagate normally.
```

The `with` statement:

1. Calls `__enter__()` — marks the session active and returns `self`
2. Runs the body
3. Calls `__exit__(exc_type, exc_val, exc_tb)` — performs zeroization, then propagates exceptions

## Behavior

| Aspect | Guarantee |
|--------|-----------|
| Exceptions | **Not suppressed** — `__exit__` returns `False`, so any error inside the block propagates to the caller after zeroization runs |
| Idempotency | Calling `__exit__` (or `_zeroize_session()`) more than once is safe |
| Nested usage | Separate cipher instances have separate buffer lists. Re-entering the same instance shares its list; an inner exit clears it and marks the instance inactive |
| Performance | Cleanup work scales with the number of registered buffers plus their total byte length; no timing benchmark is asserted |

## `__repr__`

`AegisCipher.__repr__` includes session state:

```python
>>> cipher = AegisCipher()
>>> repr(cipher)
'AegisCipher(level=SecurityLevel.ML_KEM_768, inactive)'

>>> with cipher:
...     repr(cipher)
...
'AegisCipher(level=SecurityLevel.ML_KEM_768, active)'
```

This makes it easy to verify in logs and `print()` statements that the cipher is currently inside a session.

## Internal Hook: `_register_session_buffer`

```python
def _register_session_buffer(self, buf: bytearray) -> bytearray
```

Registers a `bytearray` for proactive zeroization when the session ends. The buffer is overwritten with zeros **in place**, so any external reference to the same bytearray also sees zeros — not just the internal list.

This is an **internal API** (prefixed with `_`). It is exposed so that future AegisQ session features can register their own buffers without waiting for a public API redesign.

```python
def _zeroize_session(self) -> None:
    """Overwrite all registered buffers with zeros and clear the list."""
```

This method is called by `__exit__` and is also safe to call manually (idempotent).

## When Does It Matter?

### Current behavior

`with AegisCipher() as cipher:` changes the state displayed by `repr` and invokes the private cleanup hook on exit. It does not change the cryptographic result or erase caller-owned material. One-shot Rust cleanup is independent of the context manager.

### Future session APIs

The private registration hook is available for internal use. It is not a public `bind_session` API or a promise about future behavior.

## Complete Example with Error Handling

```python
from aegisq import AegisCipher, AegisQError, DecryptionError

cipher = AegisCipher()

# Outside the with: cipher is "inactive"
print(repr(cipher))  # AegisCipher(level=..., inactive)

try:
    with cipher:  # enters session
        print(repr(cipher))  # AegisCipher(level=..., active)
        keypair = cipher.generate_keypair()
        # Suppose a future API registers a Python-side buffer here.
        # (Today: nothing is registered.)
        package = cipher.encrypt(b"top secret", keypair.public_key)
        plaintext = cipher.decrypt(package, keypair.secret_key)
except DecryptionError:
    # __exit__ ran before the exception propagated → buffers zeroized
    print("decryption failed — context exited")
except AegisQError:
    print("another AegisQ error — context exited")

# Outside the with: cipher is back to "inactive"
print(repr(cipher))  # AegisCipher(level=..., inactive)
```

## See Also

- [`AegisCipher`](/api-reference/aegiscipher/) — main class, now with `__enter__` / `__exit__`
- [`EphemeralSession`](/api-reference/ephemeral-session/) — closes its session and drops the keypair reference
- [Security Model](/internals/security-model/) — cleanup mechanisms and limits
