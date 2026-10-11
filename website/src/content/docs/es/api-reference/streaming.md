---
title: Cifrado en Streaming
description: encrypt_stream / decrypt_stream — cifrá y descifrá payloads grandes (gigabytes y más allá) sin cargarlos en memoria.
sidebar:
  badge:
    text: v1.5.0
    variant: tip
---

[`AegisCipher`](/es/api-reference/aegiscipher/) proporciona `encrypt_stream()` y `decrypt_stream()` para **payloads grandes** — archivos, streams de red, backups — que no caben en memoria. La API está **basada en generadores**: recibe un iterable de chunks de plaintext y devuelve un iterable de chunks de ciphertext. El llamador controla el chunking de I/O.

## ¿Por qué Streaming?

La API one-shot procesa buffers completos. Streaming procesa bloques de plaintext acotados, pero el descifrado también acumula y copia fragmentos de ciphertext. La memoria depende de los tamaños y buffers del llamador; pasar varios gigabytes como un único bloque elimina el beneficio.

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

Cifra un iterable de chunks de plaintext y produce chunks de ciphertext.

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `recipient_public_key` | `bytes` | — | Clave pública ML-KEM del receptor. |
| `plaintext_chunks` | `Iterable[bytes]` | — | Cualquier iterable que produzca chunks de plaintext (típicamente un iterador de archivo). |
| `chunk_size` | `int` | `65536` (64 KiB) | Payload máximo de plaintext/ciphertext por frame, sin sus 4 bytes de longitud ni tag de 16 bytes. Rango: `1..=16 MiB`. |

**Produce:** header, frames de datos y EOF como `bytes`. Agote el generador para emitir EOF. No produzca bloques de plaintext vacíos: un frame de longitud cero se interpreta como EOF. Un iterable vacío representa un payload vacío.

**Lanza:** `InvalidParameterError` si un chunk de plaintext excede `chunk_size` o si `chunk_size` está fuera de rango; `RngError` si el CSPRNG del OS no está disponible.

### `decrypt_stream`

```python
def decrypt_stream(
    self,
    secret_key: bytes,
    ciphertext_chunks: Iterable[bytes],
) -> Iterator[bytes]
```

Descifra un iterable de chunks de ciphertext y produce chunks de plaintext.

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `secret_key` | `bytes` | — | Clave secreta ML-KEM del receptor. |
| `ciphertext_chunks` | `Iterable[bytes]` | — | Cualquier iterable que produzca chunks de ciphertext (típicamente un iterador de archivo). |

**Produce:** bloques de plaintext autenticados individualmente, antes de verificar el EOF del stream. Agote el iterador antes de considerar completo el payload.

:::caution[Finalización y framing]
Detenerse antes puede ocultar errores posteriores de autenticación o truncado. Guarde la salida provisionalmente y publíquela solo tras completar la iteración sin errores. El decoder actual se detiene en el primer EOF autenticado; no rechaza bytes posteriores ni concatena paquetes. Controle los límites de mensaje por separado.
:::

**Lanza:** `DecryptionError` si un tag de AES-GCM no verifica, si el marcador EOF falta o es inválido, o si el header del stream está truncado; `InvalidParameterError` si el header está malformado o la clave secreta tiene tamaño incorrecto.

## Transit Package — Formato en Stream

El Transit Package en stream es una secuencia auto-delimitada:

```text
┌────────────────────────────────────────┐
│ HEADER (único, producido primero)     │
│ ┌────────────────────────────────────┐ │
│ │ KEM capsule (768/1088/1568 B)      │ │
│ │ base_nonce (12 B)                  │ │
│ │ chunk_size (4 B, big-endian u32)   │ │
│ └────────────────────────────────────┘ │
├────────────────────────────────────────┤
│ FRAME (uno por chunk de plaintext)     │
│ ┌────────────────────────────────────┐ │
│ │ length (4 B, big-endian u32)       │ │
│ │ ciphertext (length B)              │ │
│ │ tag (16 B)                         │ │
│ └────────────────────────────────────┘ │
├────────────────────────────────────────┤
│ FRAME 2 ...                            │
├────────────────────────────────────────┤
│ EOF MARKER (producido al final)        │
│ ┌────────────────────────────────────┐ │
│ │ length = 0 (4 B)                   │ │
│ │ tag (16 B sobre plaintext vacío)   │ │
│ └────────────────────────────────────┘ │
└────────────────────────────────────────┘
```

### Derivación del Nonce

Cada chunk `i` (indexado desde 0) recibe un nonce de 12 bytes derivado del `base_nonce` del header:

```text
nonce_i = i.to_be_bytes() || base_nonce[4..12]
```

- `i.to_be_bytes()` son 4 bytes uint32 big-endian; EOF también consume un índice. No lo interprete como un stream ilimitado ni agote el contador
- `base_nonce[4..12]` son 8 bytes del base nonce aleatorio generado al construir el header

### AAD (Additional Authenticated Data)

El tag AES-GCM de cada chunk se computa sobre:

```text
AAD_i = i.to_be_bytes()     # 4 bytes
```

Esto vincula cada chunk a su posición en el stream, previniendo **ataques de reordenamiento de chunks** (un atacante no puede mover el frame N a la posición M sin romper la verificación del tag).

### Marcador EOF

El marcador EOF tiene `length = 0` y un tag computado sobre **plaintext vacío** con el nonce **siguiente** (índice de chunk posterior al último chunk de datos). Sirve para tres propósitos:

1. Le dice al descifrador que el stream está completo (sin truncado)
2. Autentica que el stream fue finalizado por alguien con la clave (no solo cortado)
3. Provee un punto de parada definido — `decrypt_stream` lanza `DecryptionError` si falta el marcador EOF o su tag falla la verificación

## Ejemplo Completo: Cifrar un Archivo Grande

```python
from aegisq import AegisCipher

cipher = AegisCipher()
keypair = cipher.generate_keypair()

CHUNK = 65_536  # buffer de lectura de 64 KiB

# Cifrar: archivo fuente → archivo cifrado
with open("video.mp4", "rb") as src, open("video.aegisq", "wb") as out:
    chunk_iter = iter(lambda: src.read(CHUNK), b"")
    for ct_chunk in cipher.encrypt_stream(keypair.public_key, chunk_iter):
        out.write(ct_chunk)

# Descifrar: archivo cifrado → archivo recuperado
with open("video.aegisq", "rb") as src, open("video.recovered.partial", "wb") as out:
    chunk_iter = iter(lambda: src.read(CHUNK), b"")
    for pt_chunk in cipher.decrypt_stream(keypair.secret_key, chunk_iter):
        out.write(pt_chunk)

# Solo tras verificar EOF al completar la iteración. Si falla, no publicar el archivo parcial.
from pathlib import Path
Path("video.recovered.partial").replace("video.recovered.mp4")
```

## Límites y Casos Edge

| Límite | Valor | Notas |
|--------|-------|-------|
| Rango de `chunk_size` | `1..=16 MiB` | Fuera de rango lanza `InvalidParameterError` |
| Índice de chunk | uint32 | EOF necesita otro índice; no agotar el contador |
| Tamaño del header | capsule + 16 B | 784/1104/1584 B para ML-KEM-512/768/1024 |
| Overhead por frame | 4 + 16 = 20 B | Prefijo de longitud + tag |
| Alineación de lectura | No requerida | `decrypt_stream` re-ensambla frames a través de límites de chunk |

### Streams Truncados o Manipulados

| Escenario | Comportamiento |
|-----------|----------------|
| El stream termina sin marcador EOF | `DecryptionError("stream ended without EOF marker")` |
| Header truncado antes de leer capsule + nonce + chunk_size | `DecryptionError("stream header truncated: ...")` |
| Frame truncado a mitad del ciphertext | `DecryptionError("frame truncated: expected N bytes, got M")` |
| El tag AES-GCM de un solo chunk falla | `DecryptionError` (el índice del frame puede aparecer en la cadena del error) |
| Iterador vacío pasado a `decrypt_stream` | `DecryptionError("empty stream")` |

### Defensa contra Reordenamiento de Frames

Como el AAD es `chunk_index.to_be_bytes()`, swapear dos frames causa que sus tags fallen la verificación cuando se chequean en la nueva posición. La autenticación de AES-GCM es por-chunk y constante en la clave — el reordenamiento se detecta.

## ¿Por qué Generadores (y no Corutinas)?

Los generadores permiten procesamiento incremental y control de I/O. AES-GCM nativo libera el GIL, pero un único generador procesa bloques secuencialmente; liberar el GIL no implica saturar varios cores. En asyncio, delegue el bucle completo de lectura/cifrado/escritura a un worker, no solo la creación del generador lazy.

## Ver También

- [`AegisCipher.encrypt_async` / `decrypt_async`](/es/api-reference/async-methods/) — variantes one-shot no bloqueantes
- [Context Manager de `AegisCipher`](/es/api-reference/context-manager/) — limpieza de buffers registrados internamente y sus límites
- [Hybrid KEM-DEM internals](/es/internals/hybrid-kem-dem/) — cómo se estructura el Transit Package
