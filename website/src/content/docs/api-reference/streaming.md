---
title: Streaming Encryption
description: encrypt_stream / decrypt_stream — encrypt and decrypt large payloads (gigabytes and beyond) without loading them into memory.
sidebar:
  badge:
    text: v1.5.0
    variant: tip
---

[`AegisCipher`](/api-reference/aegiscipher/) provides `encrypt_stream()` and `decrypt_stream()` for **large payloads** — files, network streams, backups — that don't fit in memory. The API is **generator-based**: you pass an iterable of plaintext chunks and get back an iterable of ciphertext chunks. The caller controls I/O chunking.

## Why Streaming?

The one-shot API processes complete byte buffers. Streaming processes bounded plaintext chunks, but decryption also buffers and copies incoming ciphertext fragments. Memory depends on the caller's chunk sizes and buffering; passing a complete multi-gigabyte input as one chunk defeats the benefit.

## API

### `encrypt_stream`

```python
def encrypt_stream(
    self,
    recipient_public_key: bytes,
    plaintext_chunks: Iterable[bytes],
    chunk_size: int = 65536,
) -> Iterator[bytes]
```

Encrypts an iterable of plaintext chunks and yields ciphertext chunks.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `recipient_public_key` | `bytes` | — | Recipient's ML-KEM public key. |
| `plaintext_chunks` | `Iterable[bytes]` | — | Any iterable producing plaintext chunks (typically a file iterator). |
| `chunk_size` | `int` | `65536` (64 KiB) | Maximum plaintext/ciphertext payload per data frame, excluding its 4-byte length and 16-byte tag. Range: `1..=16 MiB`. |

**Yields:** a header, data frames, and an EOF frame, as `bytes`. Exhaust the generator to emit EOF. Do not yield empty plaintext chunks: a zero-length frame is interpreted as EOF. An empty iterable represents an empty payload.

**Raises:** `InvalidParameterError` if a plaintext chunk exceeds `chunk_size` or `chunk_size` is out of range; `RngError` if the OS CSPRNG is unavailable.

### `decrypt_stream`

```python
def decrypt_stream(
    self,
    secret_key: bytes,
    ciphertext_chunks: Iterable[bytes],
) -> Iterator[bytes]
```

Decrypts an iterable of ciphertext chunks and yields plaintext chunks.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `secret_key` | `bytes` | — | Recipient's ML-KEM secret key. |
| `ciphertext_chunks` | `Iterable[bytes]` | — | Any iterable producing ciphertext chunks (typically a file iterator). |

**Yields:** individually authenticated plaintext chunks, before the stream's EOF is verified. Exhaust the iterator before treating the payload as complete.

:::caution[Completion and framing]
An early stop can miss a later authentication or truncation error. Stage output and publish it only after full iteration succeeds. The current decoder stops at the first authenticated EOF; it does not reject trailing bytes or concatenate multiple packages. Enforce message boundaries separately.
:::

**Raises:** `DecryptionError` if an AES-GCM tag does not verify, if the EOF marker is missing or invalid, or if the stream header is truncated; `InvalidParameterError` if the header is malformed or the secret key has the wrong size.

## Transit Package — Stream Format

The stream Transit Package is a self-delimiting sequence:

```text
┌────────────────────────────────────────┐
│ HEADER (one-shot, yielded first)       │
│ ┌────────────────────────────────────┐ │
│ │ KEM capsule (768/1088/1568 B)      │ │
│ │ base_nonce (12 B)                  │ │
│ │ chunk_size (4 B, big-endian u32)   │ │
│ └────────────────────────────────────┘ │
├────────────────────────────────────────┤
│ FRAME (one per plaintext chunk)        │
│ ┌────────────────────────────────────┐ │
│ │ length (4 B, big-endian u32)       │ │
│ │ ciphertext (length B)              │ │
│ │ tag (16 B)                         │ │
│ └────────────────────────────────────┘ │
├────────────────────────────────────────┤
│ FRAME 2 ...                            │
├────────────────────────────────────────┤
│ EOF MARKER (yielded last)              │
│ ┌────────────────────────────────────┐ │
│ │ length = 0 (4 B)                   │ │
│ │ tag (16 B over empty plaintext)    │ │
│ └────────────────────────────────────┘ │
└────────────────────────────────────────┘
```

### Nonce Derivation

Each chunk `i` (zero-indexed) gets a 12-byte nonce derived from the header's `base_nonce`:

```text
nonce_i = i.to_be_bytes() || base_nonce[4..12]
```

- `i.to_be_bytes()` is a 4-byte uint32 big-endian index; EOF also consumes an index. Do not treat this as an unlimited-stream guarantee or exhaust the counter
- `base_nonce[4..12]` is 8 bytes from the random base nonce generated at header time

### AAD (Additional Authenticated Data)

Each chunk's AES-GCM tag is computed over:

```text
AAD_i = i.to_be_bytes()     # 4 bytes
```

This binds each chunk to its position in the stream, preventing **chunk-reordering attacks** (an attacker can't move frame N to position M without breaking tag verification).

### EOF Marker

The EOF marker has `length = 0` and a tag computed over **empty plaintext** with the **next** nonce (chunk index past the last data chunk). It serves three purposes:

1. Tells the decryptor the stream is complete (no truncation)
2. Authenticates that the stream was finalized by someone with the key (not just cut off)
3. Provides a definite stopping point — `decrypt_stream` raises `DecryptionError` if the EOF marker is missing or its tag fails verification

## Complete Example: Encrypt a Large File

```python
from aegisq import AegisCipher

cipher = AegisCipher()
keypair = cipher.generate_keypair()

CHUNK = 65_536  # 64 KiB read buffer

# Encrypt: source file → encrypted file
with open("video.mp4", "rb") as src, open("video.aegisq", "wb") as out:
    chunk_iter = iter(lambda: src.read(CHUNK), b"")
    for ct_chunk in cipher.encrypt_stream(keypair.public_key, chunk_iter):
        out.write(ct_chunk)

# Decrypt: encrypted file → recovered file
with open("video.aegisq", "rb") as src, open("video.recovered.partial", "wb") as out:
    chunk_iter = iter(lambda: src.read(CHUNK), b"")
    for pt_chunk in cipher.decrypt_stream(keypair.secret_key, chunk_iter):
        out.write(pt_chunk)

# Only after full iteration verifies EOF. On failure, do not publish the partial file.
from pathlib import Path
Path("video.recovered.partial").replace("video.recovered.mp4")
```

## Limits and Edge Cases

| Limit | Value | Notes |
|-------|-------|-------|
| `chunk_size` range | `1..=16 MiB` | Out-of-range raises `InvalidParameterError` |
| Chunk index | uint32 | EOF needs an additional index; do not exhaust the counter |
| Header size | capsule + 16 B | 784/1104/1584 B for ML-KEM-512/768/1024 |
| Per-frame overhead | 4 + 16 = 20 B | Length prefix + tag |
| Read alignment | None required | `decrypt_stream` re-assembles frames across chunk boundaries |

### Truncated or Tampered Streams

| Scenario | Behavior |
|----------|----------|
| Stream ends without EOF marker | `DecryptionError("stream ended without EOF marker")` |
| Header truncated before capsule + nonce + chunk_size are read | `DecryptionError("stream header truncated: ...")` |
| Frame truncated mid-ciphertext | `DecryptionError("frame truncated: expected N bytes, got M")` |
| Single chunk's AES-GCM tag fails | `DecryptionError` (frame index may be reported in the error chain) |
| Empty input iterator to `decrypt_stream` | `DecryptionError("empty stream")` |

### Frame Reordering Defense

Because AAD is `chunk_index.to_be_bytes()`, swapping two frames causes their tags to fail verification when checked at the new position. AES-GCM authentication is per-chunk and constant in the key — reordering is detected.

## Why Generators (and not coroutines)?

Generators expose incremental processing and let the caller control I/O. Native AES-GCM operations release the GIL, but a single generator still processes chunks sequentially; GIL release does not imply multi-core saturation. For an asyncio application, offload the complete synchronous read/encrypt/write loop to a worker, rather than only constructing a lazy generator in that worker.

## See Also

- [`AegisCipher.encrypt_async` / `decrypt_async`](/api-reference/async-methods/) — non-blocking one-shot variants
- [`AegisCipher` context manager](/api-reference/context-manager/) — private buffer cleanup and its limits
- [Hybrid KEM-DEM internals](/internals/hybrid-kem-dem/) — how the Transit Package is structured
