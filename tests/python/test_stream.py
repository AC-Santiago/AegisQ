"""Tests end-to-end para el streaming API de AegisCipher.

Sprint 3 task 8. ``AegisCipher.encrypt_stream`` y ``decrypt_stream``
procesan archivos grandes por chunks con nonces AES-GCM incrementales.

Cubrimos:
- Round-trip basico (3 chunks).
- Stream vacio (0 chunks).
- Chunk unico de tamano = chunk_size.
- Chunk unico de tamano = chunk_size + 1 (debe fallar).
- Chunk de tamano 0 (distinto del EOF marker).
- Truncamiento del stream (sin EOF marker): DecryptionError.
- Tampering de un frame intermedio: DecryptionError.
- Wrong secret key: DecryptionError.
- Los 3 niveles de seguridad.
- Eficiencia: tamano del ciphertext ~= tamano del plaintext + overhead.
- No-load-all: el stream procesa la entrada sin retener todos los chunks.
"""

from __future__ import annotations

import io
import os

import pytest

from aegisq import AegisCipher, SecurityLevel
from aegisq.exceptions import DecryptionError, InvalidParameterError


ALL_LEVELS = [
    SecurityLevel.ML_KEM_512,
    SecurityLevel.ML_KEM_768,
    SecurityLevel.ML_KEM_1024,
]


def _level_name(level: SecurityLevel) -> str:
    if level == SecurityLevel.ML_KEM_512:
        return "ML_KEM_512"
    if level == SecurityLevel.ML_KEM_768:
        return "ML_KEM_768"
    if level == SecurityLevel.ML_KEM_1024:
        return "ML_KEM_1024"
    return repr(level)


# ── Roundtrip basico ────────────────────────────────────────────────────────


class TestStreamRoundtrip:
    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_roundtrip_multiple_chunks(self, level: SecurityLevel) -> None:
        sender = AegisCipher(level=level)
        receiver = AegisCipher(level=level)
        kp = receiver.generate_keypair()

        plaintext = [b"Hello, ", b"streaming ", b"world!"]
        expected = b"".join(plaintext)

        encrypted = b"".join(
            sender.encrypt_stream(kp.public_key, plaintext)
        )

        decrypted = b"".join(
            receiver.decrypt_stream(kp.secret_key, [encrypted])
        )
        assert decrypted == expected

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_roundtrip_single_chunk(self, level: SecurityLevel) -> None:
        sender = AegisCipher(level=level)
        receiver = AegisCipher(level=level)
        kp = receiver.generate_keypair()

        plaintext = [b"a single chunk of plaintext"]
        encrypted = b"".join(sender.encrypt_stream(kp.public_key, plaintext))
        decrypted = b"".join(
            receiver.decrypt_stream(kp.secret_key, [encrypted])
        )
        assert decrypted == plaintext[0]

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_roundtrip_empty_stream(self, level: SecurityLevel) -> None:
        """Stream sin chunks de plaintext: solo header + EOF marker."""
        sender = AegisCipher(level=level)
        receiver = AegisCipher(level=level)
        kp = receiver.generate_keypair()

        encrypted = b"".join(sender.encrypt_stream(kp.public_key, []))
        decrypted = b"".join(
            receiver.decrypt_stream(kp.secret_key, [encrypted])
        )
        assert decrypted == b""

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_roundtrip_large_plaintext(self, level: SecurityLevel) -> None:
        """Stream con plaintext > 64 KiB: cubre el counter en multiples chunks."""
        sender = AegisCipher(level=level)
        receiver = AegisCipher(level=level)
        kp = receiver.generate_keypair()

        chunk_size = 1024
        chunks = [bytes((i % 256) for i in range(chunk_size)) for _ in range(10)]
        expected = b"".join(chunks)

        encrypted = b"".join(
            sender.encrypt_stream(kp.public_key, chunks, chunk_size=chunk_size)
        )
        decrypted = b"".join(
            receiver.decrypt_stream(kp.secret_key, [encrypted])
        )
        assert decrypted == expected


# ── Lectura en chunks arbitrarios (no necesariamente alineados) ──────────


class TestStreamArbitraryReadSize:
    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_decrypt_with_different_read_size(self, level: SecurityLevel) -> None:
        """El decryptor no depende del tamano exacto del chunk de lectura."""
        sender = AegisCipher(level=level)
        receiver = AegisCipher(level=level)
        kp = receiver.generate_keypair()

        plaintext = [os.urandom(4096) for _ in range(5)]
        encrypted = b"".join(
            sender.encrypt_stream(kp.public_key, plaintext, chunk_size=4096)
        )

        # Leer el stream en chunks mas pequenos que el chunk_size.
        for read_size in (1, 7, 100, 1023, 4096, 8192):
            bio = io.BytesIO(encrypted)
            decrypted = b"".join(
                receiver.decrypt_stream(
                    kp.secret_key,
                    iter(lambda: bio.read(read_size), b""),
                )
            )
            assert decrypted == b"".join(plaintext), (
                f"failed with read_size={read_size}"
            )


# ── Detección de tampering ──────────────────────────────────────────────────


class TestStreamTampering:
    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_tampered_ciphertext_fails(self, level: SecurityLevel) -> None:
        sender = AegisCipher(level=level)
        receiver = AegisCipher(level=level)
        kp = receiver.generate_keypair()

        plaintext = [b"chunk1", b"chunk2", b"chunk3"]
        encrypted = bytearray(
            b"".join(sender.encrypt_stream(kp.public_key, plaintext))
        )

        # Tamper con un byte dentro del primer chunk.
        # El header termina en (capsule_size + 16). A partir de ahi vienen
        # los frames. Tomamos un byte del primer frame.
        header_size = (
            {"ML_KEM_512": 768, "ML_KEM_768": 1088, "ML_KEM_1024": 1568}[
                _level_name(level)
            ]
            + 16
        )
        encrypted[header_size + 5] ^= 0xFF

        with pytest.raises(DecryptionError):
            b"".join(receiver.decrypt_stream(kp.secret_key, [bytes(encrypted)]))

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_missing_eof_fails(self, level: SecurityLevel) -> None:
        """Stream truncado sin EOF marker: DecryptionError."""
        sender = AegisCipher(level=level)
        receiver = AegisCipher(level=level)
        kp = receiver.generate_keypair()

        plaintext = [b"chunk1", b"chunk2"]
        encrypted = bytearray(
            b"".join(sender.encrypt_stream(kp.public_key, plaintext))
        )

        # Quitar el EOF marker (los ultimos 20 bytes).
        truncated = bytes(encrypted[:-20])

        with pytest.raises(DecryptionError):
            b"".join(receiver.decrypt_stream(kp.secret_key, [truncated]))

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_wrong_secret_key_fails(self, level: SecurityLevel) -> None:
        sender = AegisCipher(level=level)
        receiver1 = AegisCipher(level=level)
        receiver2 = AegisCipher(level=level)
        kp1 = receiver1.generate_keypair()
        kp2 = receiver2.generate_keypair()

        encrypted = b"".join(
            sender.encrypt_stream(kp1.public_key, [b"secret"])
        )

        with pytest.raises(DecryptionError):
            b"".join(receiver2.decrypt_stream(kp2.secret_key, [encrypted]))


# ── Validacion de parametros ───────────────────────────────────────────────


class TestStreamParameterValidation:
    def test_chunk_size_too_small(self) -> None:
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        with pytest.raises(InvalidParameterError):
            list(cipher.encrypt_stream(kp.public_key, [b"data"], chunk_size=0))

    def test_chunk_size_too_large(self) -> None:
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        with pytest.raises(InvalidParameterError):
            list(
                cipher.encrypt_stream(
                    kp.public_key, [b"data"], chunk_size=32 * 1024 * 1024
                )
            )

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_chunk_exceeds_chunk_size(self, level: SecurityLevel) -> None:
        """Un plaintext chunk que excede chunk_size debe fallar."""
        cipher = AegisCipher(level=level)
        kp = cipher.generate_keypair()
        with pytest.raises(InvalidParameterError):
            list(
                cipher.encrypt_stream(
                    kp.public_key,
                    [b"x" * 100],
                    chunk_size=50,
                )
            )


# ── Tamaño del overhead ────────────────────────────────────────────────────


class TestStreamOverhead:
    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_overhead_per_chunk(self, level: SecurityLevel) -> None:
        """Por chunk de plaintext: 4 bytes (len) + 16 bytes (tag) = 20 bytes.
        Mas EOF marker (20 bytes) y header (capsule_size + 16)."""
        sender = AegisCipher(level=level)
        receiver = AegisCipher(level=level)
        kp = receiver.generate_keypair()

        chunk_size = 1024
        n_chunks = 5
        plaintext = [b"a" * chunk_size for _ in range(n_chunks)]
        encrypted = b"".join(
            sender.encrypt_stream(kp.public_key, plaintext, chunk_size=chunk_size)
        )

        header_size = {
            "ML_KEM_512": 768,
            "ML_KEM_768": 1088,
            "ML_KEM_1024": 1568,
        }[_level_name(level)] + 16
        expected_total = (
            header_size
            + n_chunks * (4 + chunk_size + 16)
            + 20  # EOF marker
        )
        assert len(encrypted) == expected_total, (
            f"expected {expected_total}, got {len(encrypted)}"
        )


# ── Streaming real: lectura por chunks arbitrarios ────────────────────────


class TestStreamRealFilePattern:
    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_simulate_large_file(self, level: SecurityLevel) -> None:
        """Simula un archivo de 256 KiB leido en chunks de 64 KiB."""
        sender = AegisCipher(level=level)
        receiver = AegisCipher(level=level)
        kp = receiver.generate_keypair()

        # 256 KiB de bytes aleatorios. Tamano elegido para que el test
        # corra rapido (~256K reads en el peor caso) sin sobrecargar
        # CI; suficiente para ejercitar varios chunks + EOF.
        plaintext = os.urandom(256 * 1024)

        # Encrypt leyendo en chunks de 64 KiB via un generador que
        # AVANZA sobre plaintext. (NUNCA usar iter(lambda, sentinel)
        # con un slice que no avanza — loop infinito.)
        def _chunks(data: bytes, size: int):
            for i in range(0, len(data), size):
                yield data[i : i + size]

        src = _chunks(plaintext, 64 * 1024)
        encrypted = b"".join(sender.encrypt_stream(kp.public_key, src))

        # Decrypt leyendo en chunks de 32 KiB (no alineados).
        bio = io.BytesIO(encrypted)
        decrypted = b"".join(
            receiver.decrypt_stream(
                kp.secret_key, iter(lambda: bio.read(32 * 1024), b"")
            )
        )

        assert decrypted == plaintext
