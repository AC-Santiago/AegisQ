"""Clase AegisCipher — API de alto nivel para cifrado hibrido post-cuantico.

Esta es la clase principal que los usuarios finales deben usar.
Abstrae todo el flujo KEM-DEM (ML-KEM + AES-256-GCM) en una interfaz
simple de ``encrypt()`` / ``decrypt()``.

Ejemplo::

    from aegisq import AegisCipher, SecurityLevel

    # Receptor genera su keypair
    cipher_bob = AegisCipher(level=SecurityLevel.ML_KEM_768)
    keypair = cipher_bob.generate_keypair()

    # Emisor cifra con la clave publica del receptor
    cipher_alice = AegisCipher(level=SecurityLevel.ML_KEM_768)
    package = cipher_alice.encrypt(
        plaintext=b"Datos secretos",
        recipient_public_key=keypair.public_key,
    )

    # Receptor descifra
    plaintext = cipher_bob.decrypt(
        encrypted_package=package,
        secret_key=keypair.secret_key,
    )

Streaming para archivos grandes (v1.5.0)::

    with open("video.mp4", "rb") as f:
        src = iter(lambda: f.read(65536), b"")
        with open("video.aegisq", "wb") as out:
            for ct_chunk in cipher.encrypt_stream(pk, src):
                out.write(ct_chunk)

Como **context manager** (zeroizacion proactiva al salir)::

    with AegisCipher(level=SecurityLevel.ML_KEM_768) as cipher:
        kp = cipher.generate_keypair()
        pkg = cipher.encrypt(b"hola", kp.public_key)
        # __exit__ zeroiza proactivamente cualquier buffer Python-side
        # registrado durante la sesion.

Nota sobre zeroizacion:
    Hoy ``encrypt()`` y ``decrypt()`` son one-shot: el shared secret se
    deriva y zeroiza dentro de Rust (via wrappers ``Zeroizing``) en cada
    llamada, sin retencion Python-side. El context manager se
    proporciona como contrato forward-compatible: si una API futura
    mantiene material criptografico Python-side, ese material se
    registra con ``_register_session_buffer`` y se zeroiza
    deterministicamente al salir del ``with``, sin depender del GC.
"""

from __future__ import annotations

from __future__ import annotations

import asyncio
import struct
from typing import Iterable, Iterator, Self

from aegisq._aegisq_core import (
    KeyPair,
    SecurityLevel,
    decrypt_hybrid,
    encrypt_hybrid,
    generate_keypair,
    stream_decryptor_from_header,
    stream_encryptor_new,
)
from aegisq.exceptions import DecryptionError, InvalidParameterError


# ── Helpers para decrypt_stream parsing ────────────────────────────────────

# Tamano del KEM capsule segun el nivel ML-KEM. Igual que en
# `_aegisq_core::kem::SecurityLevel::capsule_size`. Mantenido explicito
# aqui para no exponer implementacion Capa 1 via Python.
# (Usamos if/elif porque SecurityLevel (PyO3) no es hashable en Python.)


def _capsule_size(level: SecurityLevel) -> int:
    if level == SecurityLevel.ML_KEM_512:
        return 768
    if level == SecurityLevel.ML_KEM_768:
        return 1088
    if level == SecurityLevel.ML_KEM_1024:
        return 1568
    raise ValueError(f"unknown SecurityLevel: {level!r}")


def _stream_chunk_size_dec(dec: object) -> int:
    """Lee el chunk_size configurado en el decryptor."""
    return int(dec.chunk_size())


def _frame_iter(
    iterator: Iterator[bytes],
    buffer: bytearray,
    header_size: int,
    chunk_size: int,
) -> Iterator[tuple[int, bytes, bytes]]:
    """Lee frames `[len (4B BE) | ciphertext (len B) | tag (16B)]` desde
    un iterador de chunks, devolviendo tuplas (length, ciphertext, tag).

    Yield: ``(length, ciphertext_bytes, tag_bytes)`` por cada frame.
    Termina cuando el iterador se agota; el caller verifica el EOF
    marker (length == 0).
    """
    while True:
        # Asegurar que tenemos al menos 4 bytes para el len.
        while len(buffer) < 4:
            try:
                buffer.extend(next(iterator))
            except StopIteration:
                return  # EOF sin suficiente data para len

        length = struct.unpack(">I", bytes(buffer[:4]))[0]
        if length > chunk_size:
            raise DecryptionError(
                f"frame length {length} exceeds chunk_size {chunk_size}"
            )
        needed = 4 + length + 16
        while len(buffer) < needed:
            try:
                buffer.extend(next(iterator))
            except StopIteration:
                raise DecryptionError(
                    f"frame truncated: expected {needed} bytes, got {len(buffer)}"
                )

        # Extraer el frame completo del buffer.
        frame = bytes(buffer[:needed])
        del buffer[:needed]

        ciphertext = frame[4 : 4 + length]
        tag = frame[4 + length : 4 + length + 16]
        yield (length, ciphertext, tag)


class AegisCipher:
    """Motor de cifrado hibrido post-cuantico (ML-KEM + AES-256-GCM).

    Args:
        level: Nivel de seguridad ML-KEM. Por defecto ``SecurityLevel.ML_KEM_768``.

    Soporta uso como **context manager**. Al salir del bloque ``with``, se
    zeroizan proactivamente todos los buffers Python-side registrados
    durante la sesion. Hoy la API publica no retiene material; el
    protocolo existe para forward-compatibility con futuras APIs de
    sesion / streaming.
    """

    def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None:
        self._level = level
        self._entered: bool = False
        # Buffers Python-side retenidos durante la sesion. Cada uno es
        # un bytearray para que podamos sobrescribir su contenido in-place.
        self._session_buffers: list[bytearray] = []

    @property
    def level(self) -> SecurityLevel:
        """Nivel de seguridad configurado."""
        return self._level

    def generate_keypair(self) -> KeyPair:
        """Genera un par de claves ML-KEM para este nivel de seguridad.

        Returns:
            KeyPair con ``public_key`` y ``secret_key`` como ``bytes``.

        Raises:
            RngError: Si el CSPRNG del sistema operativo no esta disponible.
        """
        return generate_keypair(self._level)

    def encrypt(
        self,
        plaintext: bytes,
        recipient_public_key: bytes,
    ) -> bytes:
        """Cifra datos usando el esquema hibrido ML-KEM + AES-256-GCM.

        Flujo interno:
            1. ML-KEM.Encaps genera capsule + shared_secret
            2. AES-256-GCM cifra plaintext con shared_secret como clave
            3. Ensambla el Transit Package

        Args:
            plaintext: Datos a cifrar (cualquier longitud).
            recipient_public_key: Clave publica ML-KEM del receptor.

        Returns:
            Transit Package como ``bytes``:
            ``[ML-KEM Capsule | AES Nonce (12B) | Auth Tag (16B) | Ciphertext]``

        Raises:
            InvalidParameterError: Si la clave publica tiene tamano incorrecto.
            RngError: Si el CSPRNG del OS no esta disponible.
        """
        return bytes(encrypt_hybrid(recipient_public_key, plaintext, self._level))

    def decrypt(
        self,
        encrypted_package: bytes,
        secret_key: bytes,
    ) -> bytes:
        """Descifra un Transit Package usando la clave secreta.

        Args:
            encrypted_package: Transit Package completo recibido.
            secret_key: Clave secreta ML-KEM propia.

        Returns:
            Plaintext original como ``bytes``.

        Raises:
            DecryptionError: Si el Auth Tag de AES-GCM es invalido
                (payload manipulado o clave incorrecta).
            InvalidParameterError: Si el paquete tiene tamano incorrecto.
        """
        return bytes(decrypt_hybrid(encrypted_package, secret_key, self._level))

    # ── Streaming (v1.5.0) ────────────────────────────────────────────────

    def encrypt_stream(
        self,
        recipient_public_key: bytes,
        plaintext_chunks: Iterable[bytes],
        chunk_size: int = 65536,
    ) -> Iterator[bytes]:
        """Cifra un iterable de plaintext chunks, yieldando ciphertext chunks.

        Formato del Transit Package (modo stream):

        * Header: ``[KEM capsule | base_nonce (12B) | chunk_size (4B BE u32)]``
        * Cada frame: ``[len (4B BE u32) | ciphertext (len B) | tag (16B)]``
        * EOF marker: ``[len = 0 | tag (16B sobre plaintext vacio)]``

        El nonce AES-GCM del chunk ``i`` deriva de
        ``i.to_be_bytes() || base_nonce[4..12]``. El AAD es
        ``i.to_be_bytes()`` (4 bytes).

        Args:
            recipient_public_key: clave publica ML-KEM del receptor.
            plaintext_chunks: iterable que produce plaintext chunks. El
                caller controla el chunking (recomendado: 64 KiB).
            chunk_size: tamano maximo del ciphertext por chunk (1..=16 MiB).
                Default 64 KiB.

        Yields:
            Iterador de bytes. La primera chunk yielded es el header; las
            siguientes son frames; la ultima es el EOF marker.

        Ejemplo::

            with open("video.mp4", "rb") as f:
                src = iter(lambda: f.read(65536), b"")
                with open("video.aegisq", "wb") as out:
                    for ct in cipher.encrypt_stream(pk, src):
                        out.write(ct)

        Raises:
            InvalidParameterError: Si un plaintext chunk excede ``chunk_size``
                o si el ML-KEM encaps falla.
            RngError: Si el CSPRNG del OS no esta disponible.
        """
        if chunk_size < 1 or chunk_size > 16 * 1024 * 1024:
            raise InvalidParameterError(
                f"chunk_size must be 1..=16 MiB, got {chunk_size}"
            )

        header, enc = stream_encryptor_new(
            recipient_public_key, chunk_size, self._level
        )
        # Yield del header: el primer chunk del Transit Package.
        yield bytes(header)

        for chunk in plaintext_chunks:
            yield bytes(enc.encrypt_chunk(chunk))

        # EOF marker: cierra el stream unicamente si se genero al menos
        # un frame. Como yield es lazy, esto corre cuando el consumer
        # itera hasta el final.
        yield bytes(enc.finalize())

    def decrypt_stream(
        self,
        secret_key: bytes,
        ciphertext_chunks: Iterable[bytes],
    ) -> Iterator[bytes]:
        """Descifra un iterable de ciphertext chunks, yieldando plaintext.

        El primer chunk del iterable debe ser el header
        ``[capsule | base_nonce | chunk_size]``. Los siguientes son
        frames ``[len | ciphertext | tag]``. El EOF marker (len=0)
        debe estar presente al final; su ausencia levanta
        ``DecryptionError``.

        Args:
            secret_key: clave secreta ML-KEM del receptor.
            ciphertext_chunks: iterable que produce ciphertext chunks.
                El caller controla el chunking (puede leer bloques
                arbitrarios; la API reensambla los frames).

        Yields:
            Iterador de plaintext chunks.

        Raises:
            DecryptionError: Si un tag AES-GCM no verifica, o si el EOF
                marker falta o es invalido.
            InvalidParameterError: Si el header esta malformado o la
                clave secreta tiene tamano incorrecto.
        """
        iterator = iter(ciphertext_chunks)

        try:
            first = next(iterator)
        except StopIteration:
            raise DecryptionError("empty stream")

        # El primer chunk yielded por encrypt_stream es el header.
        # En el consumer, el primer chunk que llega puede ser mas
        # pequeno que el header (boundary issue), asi que necesitamos
        # concatenar hasta tener el header completo.
        level_capsule = _capsule_size(self._level)
        header_size = level_capsule + 12 + 4  # capsule + base_nonce + chunk_size
        buffer = bytearray(first)
        while len(buffer) < header_size:
            try:
                buffer.extend(next(iterator))
            except StopIteration:
                raise DecryptionError(
                    "stream header truncated: expected "
                    f"{header_size} bytes, got {len(buffer)}"
                )

        header_bytes = bytes(buffer[:header_size])
        # Cualquier byte extra del primer chunk es el primer frame.
        leftover = bytes(buffer[header_size:])

        # Crear el decryptor desde el header.
        dec = stream_decryptor_from_header(
            header_bytes, secret_key, self._level
        )

        # Parsear el primer frame (puede venir completo en el primer
        # chunk del input, o seguir en los subsiguientes).
        chunk_size = _stream_chunk_size_dec(dec)
        eof_seen = False

        frame_buffer = bytearray(leftover)
        frames = _frame_iter(iterator, frame_buffer, header_size, chunk_size)

        for frame in frames:
            length, ciphertext, tag = frame
            if length == 0:
                # EOF marker
                dec.process_eof(tag)
                eof_seen = True
                break
            yield bytes(dec.decrypt_chunk(ciphertext, tag))

        if not eof_seen:
            raise DecryptionError("stream ended without EOF marker")

    def __repr__(self) -> str:
        state = "active" if self._entered else "inactive"
        return f"AegisCipher(level={self._level!r}, {state})"

    # ── Context manager: zeroizacion proactiva al salir ──────────────────────

    def __enter__(self) -> Self:
        """Marca la sesion como activa y devuelve ``self``.

        Usar dentro de un bloque ``with``::

            with AegisCipher() as cipher:
                cipher.encrypt(b"...", pk)
                # __exit__ zeroiza proactivamente cualquier buffer
                # Python-side registrado durante la sesion.
        """
        self._entered = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Sale del contexto zeroizando proactivamente los buffers retenidos.

        No suprime excepciones: cualquier error dentro del bloque ``with``
        se propaga al llamador despues de la zeroizacion.
        """
        self._zeroize_session()
        return False  # do not suppress exceptions

    def _register_session_buffer(self, buf: bytearray) -> bytearray:
        """Registra un ``bytearray`` para zeroizacion proactiva al ``__exit__``.

        API interna usada por futuras features (ej. ``bind_session``,
        ``encrypt_stream``) que retengan material criptografico Python-side.
        El material se sobrescribe con ceros deterministicamente al salir
        del contexto, sin depender de la recoleccion de basura.

        Args:
            buf: buffer mutable a registrar (se modifica in-place).

        Returns:
            El mismo buffer (para encadenar).
        """
        self._session_buffers.append(buf)
        return buf

    def _zeroize_session(self) -> None:
        """Sobrescribe con ceros todos los buffers registrados y limpia la lista.

        Llamado por ``__exit__``. Idempotente: invocarlo multiples veces
        es seguro. No lanza excepciones si no hay buffers registrados.
        """
        for buf in self._session_buffers:
            # Sobrescribimos in-place para que cualquier referencia
            # externa al bytearray vea ceros, no solo esta lista.
            for i in range(len(buf)):
                buf[i] = 0
        self._session_buffers.clear()
        self._entered = False

    async def encrypt_async(
        self,
        plaintext: bytes,
        recipient_public_key: bytes,
    ) -> bytes:
        """Cifra datos de forma asincrona usando el esquema hibrido.

        Este metodo ejecuta la operacion de cifrado en un ThreadPoolExecutor
        sin bloquear el event loop. No requiere cambios en Rust ni PyO3.

        Args:
            plaintext: Datos a cifrar (cualquier longitud).
            recipient_public_key: Clave publica ML-KEM del receptor.

        Returns:
            Transit Package como ``bytes``:
            ``[ML-KEM Capsule | AES Nonce (12B) | Auth Tag (16B) | Ciphertext]``

        Raises:
            InvalidParameterError: Si la clave publica tiene tamano incorrecto.
            RngError: Si el CSPRNG del OS no esta disponible.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self.encrypt,
            plaintext,
            recipient_public_key,
        )

    async def decrypt_async(
        self,
        encrypted_package: bytes,
        secret_key: bytes,
    ) -> bytes:
        """Descifra un Transit Package de forma asincrona.

        Este metodo ejecuta la operacion de descifrado en un ThreadPoolExecutor
        sin bloquear el event loop. No requiere cambios en Rust ni PyO3.

        Args:
            encrypted_package: Transit Package completo recibido.
            secret_key: Clave secreta ML-KEM propia.

        Returns:
            Plaintext original como ``bytes``.

        Raises:
            DecryptionError: Si el Auth Tag de AES-GCM es invalido
                (payload manipulado o clave incorrecta).
            InvalidParameterError: Si el paquete tiene tamano incorrecto.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self.decrypt,
            encrypted_package,
            secret_key,
        )
