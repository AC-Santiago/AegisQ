---
title: Context Manager
description: AegisCipher as a context manager — proactive zeroization of any Python-side session buffers on exit.
sidebar:
  badge:
    text: v1.4.0
    variant: tip
---

[`AegisCipher`](/api-reference/aegiscipher/) implements the Python **context manager protocol** (`__enter__` / `__exit__`). When the `with` block exits, any Python-side buffer that was registered during the session is **overwritten with zeros in place** before the cipher object is returned to its caller.

This is a **forward-compatible hook**: today's public API (`encrypt` / `decrypt` / `encrypt_stream` / `decrypt_stream`) doesn't retain Python-side cryptographic material beyond the call boundary — the shared secret lives in Rust, wrapped in `Zeroizing`, and is wiped when each call returns. The context manager exists so that **future session-aware APIs** (e.g. `bind_session`, multi-message encryption, long-running streams) can register any persistent Python-side buffer and rely on deterministic zeroization on exit, not on the garbage collector.

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
| Nested usage | Each `with AegisCipher() as c:` is a fresh session; nested blocks are allowed but each registers buffers independently |
| Performance | Zeroization is `O(n)` in the number of registered buffers and their total size; negligible vs. a single AES-GCM operation |

## `__repr__`

`AegisCipher.__repr__` includes session state:

```python
>>> cipher = AegisCipher()
>>> repr(cipher)
'AegisCipher(level=<SecurityLevel.ML_KEM_768>, inactive)'

>>> with cipher:
...     repr(cipher)
...
'AegisCipher(level=<SecurityLevel.ML_KEM_768>, active)'
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

### Today (v1.5.0)

You can use `with AegisCipher() as cipher:` purely as a **documentation / forward-compatibility habit**. There's no observable difference vs. using the cipher without `with`. The shared-secret lifetime is already controlled by Rust `Zeroizing`.

### Future session APIs

When AegisQ ships APIs that retain Python-side material across multiple calls (e.g. a session key bound to a remote peer, or a streaming cipher whose nonce state lives in Python), those APIs will call `_register_session_buffer()` internally. Your existing `with` blocks will then **automatically benefit** without code changes — the registered buffer is zeroized on exit.

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
    print("decryption failed — already zeroized")
except AegisQError:
    print("any other AegisQ error — already zeroized")

# Outside the with: cipher is back to "inactive"
print(repr(cipher))  # AegisCipher(level=..., inactive)
```

## See Also

- [`AegisCipher`](/api-reference/aegiscipher/) — main class, now with `__enter__` / `__exit__`
- [`EphemeralSession`](/api-reference/ephemeral-session/) — uses its own context manager to destroy its ephemeral keypair
- [Security Model](/internals/security-model/) — broader zeroization guarantees
