"""Tests de serializacion de llaves ML-KEM (v1.3.0).

Cubre los formatos PEM-like y JSON para llaves publicas, y el blob
binario cifrado con contrasena (AES-256-GCM + HKDF-SHA3-256) para
llaves privadas, segun spec §1.11.

Organizacion:
- TestPublicKeyPEM: round-trip, header/footer, line length
- TestPublicKeyJSON: round-trip, contiene campo level
- TestSecretKeyWrapUnwrap: cifrado/descifrado + verificacion de seguridad
- TestFileIO: save/load archivos en disco
- TestErrorHandling: errores de formato malformado
"""

import pytest

from aegisq import (
    AegisCipher,
    KeySerializationError,
    SecurityLevel,
)
from aegisq._aegisq_core import load_secret_key_raw
from aegisq.exceptions import DecryptionError
from aegisq.keys import (
    load_public_key,
    load_secret_key,
    save_public_key,
    save_secret_key,
)

# ── Constantes de formato ─────────────────────────────────────────────────

PEM_PUBLIC_HEADER = "-----BEGIN ML-KEM PUBLIC KEY-----"
PEM_PUBLIC_FOOTER = "-----END ML-KEM PUBLIC KEY-----"
PEM_ENCRYPTED_HEADER = "-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----"
PEM_ENCRYPTED_FOOTER = "-----END ENCRYPTED ML-KEM PRIVATE KEY-----"
BLOB_MAGIC = b"AQPK"

# ── Helper para generar un KeyPair fresco ────────────────────────────────


def _fresh_keypair(level: SecurityLevel):
    cipher = AegisCipher(level=level)
    return cipher.generate_keypair()


def _level_name(level: SecurityLevel) -> str:
    """Retorna el nombre string del nivel (ej: ML_KEM_768).

    SecurityLevel (PyO3 #[pyclass] eq_int) NO tiene .name como enum.Enum
    de Python y NO acepta int() directamente. Usamos comparacion por igualdad
    contra los singletons que importamos.
    """
    if level == SecurityLevel.ML_KEM_512:
        return "ML_KEM_512"
    if level == SecurityLevel.ML_KEM_768:
        return "ML_KEM_768"
    if level == SecurityLevel.ML_KEM_1024:
        return "ML_KEM_1024"
    raise ValueError(f"Unknown SecurityLevel: {level!r}")


# ──────────────────────────────────────────────────────────────────────────
# Llave publica en formato PEM
# ──────────────────────────────────────────────────────────────────────────


class TestPublicKeyPEM:
    """PEM-like con header/footer propietarios y Base64 STANDARD."""

    @pytest.mark.parametrize(
        "level",
        [
            SecurityLevel.ML_KEM_512,
            SecurityLevel.ML_KEM_768,
            SecurityLevel.ML_KEM_1024,
        ],
    )
    def test_public_key_pem_roundtrip(self, level: SecurityLevel) -> None:
        """PEM generado por public_key_pem() debe cargarse identico al original."""
        keypair = _fresh_keypair(level)
        pem = keypair.public_key_pem()

        from aegisq._aegisq_core import load_public_key_pem

        recovered = load_public_key_pem(pem, level)

        assert recovered == keypair.public_key, (
            "PEM roundtrip debe recuperar exactamente los bytes de la pk original"
        )

    def test_public_key_pem_header_footer_format(self) -> None:
        """El PEM debe tener exactamente el header y footer propietarios."""
        keypair = _fresh_keypair(SecurityLevel.ML_KEM_768)
        pem = keypair.public_key_pem()

        assert pem.startswith(PEM_PUBLIC_HEADER), (
            f"PEM debe empezar con header propietario, got: {pem[:50]!r}"
        )
        assert PEM_PUBLIC_FOOTER in pem, (
            f"PEM debe contener footer propietario, got: ...{pem[-50:]!r}"
        )

    def test_public_key_pem_line_length_64(self) -> None:
        """Las lineas del cuerpo Base64 no deben exceder 64 chars."""
        keypair = _fresh_keypair(SecurityLevel.ML_KEM_768)
        pem = keypair.public_key_pem()

        # Extraer lineas entre header y footer.
        lines = pem.strip().split("\n")
        # Linea 0 = header, linea N = footer; el resto son body.
        body_lines = lines[1:-1]
        assert len(body_lines) > 0, "PEM debe tener al menos una linea de body"

        # Todas las lineas intermedias (NO la ultima) deben tener exactamente 64 chars.
        # La ultima puede ser mas corta porque Base64 rellena con '=' solo al final.
        for i, line in enumerate(body_lines[:-1]):
            assert len(line) == 64, (
                f"Linea intermedia #{i} debe tener exactamente 64 chars, "
                f"got {len(line)}: {line!r}"
            )
        # La ultima linea puede ser mas corta (>= 1 char, <= 64).
        last_line = body_lines[-1]
        assert 1 <= len(last_line) <= 64, (
            f"Ultima linea debe tener entre 1 y 64 chars, got {len(last_line)}: {last_line!r}"
        )


# ──────────────────────────────────────────────────────────────────────────
# Llave publica en formato JSON
# ──────────────────────────────────────────────────────────────────────────


class TestPublicKeyJSON:
    """JSON con campos algorithm/level/public_key."""

    def test_public_key_json_roundtrip(self) -> None:
        """JSON generado debe cargarse y recuperar bytes + nivel."""
        import json

        keypair = _fresh_keypair(SecurityLevel.ML_KEM_768)
        js_str = keypair.public_key_json()

        # Validar estructura JSON.
        parsed = json.loads(js_str)
        assert parsed["algorithm"] == "ML-KEM"
        assert parsed["level"] == "ML_KEM_768"
        assert "public_key" in parsed

        # Round-trip via la API de carga.
        from aegisq._aegisq_core import load_public_key_json

        recovered_pk, recovered_level = load_public_key_json(js_str)
        assert recovered_pk == keypair.public_key
        assert recovered_level == SecurityLevel.ML_KEM_768

    def test_public_key_json_contains_level_field(self) -> None:
        """El JSON debe contener el campo level como string UPPER_CASE."""
        import json

        for level in [
            SecurityLevel.ML_KEM_512,
            SecurityLevel.ML_KEM_768,
            SecurityLevel.ML_KEM_1024,
        ]:
            keypair = _fresh_keypair(level)
            parsed = json.loads(keypair.public_key_json())

            expected_name = _level_name(level)
            assert parsed["level"] == expected_name, (
                f"JSON debe contener level={expected_name!r}, got {parsed['level']!r}"
            )


# ──────────────────────────────────────────────────────────────────────────
# Llave secreta cifrada (wrap/unwrap)
# ──────────────────────────────────────────────────────────────────────────


class TestSecretKeyWrapUnwrap:
    """AES-256-GCM + HKDF-SHA3-256 sobre la secret key."""

    def test_secret_key_wrap_unwrap_roundtrip(self) -> None:
        """Wrap + unwrap con contrasena correcta recupera bytes originales."""
        keypair = _fresh_keypair(SecurityLevel.ML_KEM_768)
        password = b"correct-horse-battery-staple"

        blob = keypair.export_secret_key_raw(password)
        assert isinstance(blob, bytes)
        assert len(blob) > 0

        recovered_sk, recovered_level = load_secret_key_raw(blob, password)
        assert recovered_sk == keypair.secret_key
        assert recovered_level == SecurityLevel.ML_KEM_768

    def test_secret_key_wrong_password_raises_decryption_error(self) -> None:
        """Contrasena incorrecta debe lanzar DecryptionError (no KeySerializationError)."""
        keypair = _fresh_keypair(SecurityLevel.ML_KEM_768)
        blob = keypair.export_secret_key_raw(b"correct-password")

        with pytest.raises(DecryptionError):
            load_secret_key_raw(blob, b"WRONG-password")

    def test_secret_key_pem_header_footer_format(self) -> None:
        """El PEM de la sk cifrada debe tener header ENCRYPTED propietario."""
        keypair = _fresh_keypair(SecurityLevel.ML_KEM_768)
        pem = keypair.export_secret_key_pem(b"pwd")

        assert pem.startswith(PEM_ENCRYPTED_HEADER)
        assert PEM_ENCRYPTED_FOOTER in pem

    def test_secret_key_blob_magic_bytes(self) -> None:
        """El blob raw debe empezar con los magic bytes 'AQPK'."""
        keypair = _fresh_keypair(SecurityLevel.ML_KEM_768)
        blob = keypair.export_secret_key_raw(b"pwd")

        assert blob[:4] == BLOB_MAGIC, (
            f"Blob debe empezar con magic {BLOB_MAGIC!r}, got {blob[:4]!r}"
        )
        # Version = 1 (byte 4), level_id = 1 para ML_KEM_768 (byte 5)
        assert blob[4] == 1, f"Version debe ser 1, got {blob[4]}"
        assert blob[5] == 1, f"level_id para ML_KEM_768 debe ser 1, got {blob[5]}"

    def test_export_secret_key_never_exposes_raw_in_pem(self) -> None:
        """Verificacion CRITICA de seguridad: los bytes de secret_key NO
        deben aparecer literalmente en el PEM cifrado.
        """
        keypair = _fresh_keypair(SecurityLevel.ML_KEM_768)

        # Usar un secret_key con patron reconocible (no aleatorio puro).
        # Esto aumenta la probabilidad de detectar filtracion literal.
        # Como keypair.secret_key es aleatorio, agarramos 32 bytes del medio
        # y los buscamos como substring en el PEM.
        sample = bytes(keypair.secret_key[100:132])  # 32 bytes unicos

        pem = keypair.export_secret_key_pem(b"pwd")

        assert sample not in pem.encode("utf-8"), (
            "BUG DE SEGURIDAD: bytes de secret_key aparecen literalmente "
            "en el PEM cifrado. El cifrado AES-GCM no esta funcionando."
        )


# ──────────────────────────────────────────────────────────────────────────
# File I/O (save/load a disco)
# ──────────────────────────────────────────────────────────────────────────


class TestFileIO:
    """save_* / load_* escriben y leen archivos correctamente."""

    def test_save_and_load_public_key_file_pem(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        pem_path = tmp_path / "recipient.pem"  # type: ignore[operator]
        keypair = _fresh_keypair(SecurityLevel.ML_KEM_768)

        save_public_key(keypair, pem_path)
        assert pem_path.exists()
        assert pem_path.stat().st_size > 0

        recovered = load_public_key(pem_path, level=SecurityLevel.ML_KEM_768)
        assert recovered == keypair.public_key

    def test_save_and_load_public_key_file_json(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        json_path = tmp_path / "recipient.json"  # type: ignore[operator]
        keypair = _fresh_keypair(SecurityLevel.ML_KEM_768)

        save_public_key(keypair, json_path, fmt="json")
        assert json_path.exists()

        # Para JSON el level se extrae del archivo, no se pasa.
        recovered = load_public_key(json_path)
        assert recovered == keypair.public_key

    def test_save_and_load_secret_key_file(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        sk_path = tmp_path / "private.key"  # type: ignore[operator]
        keypair = _fresh_keypair(SecurityLevel.ML_KEM_768)
        password = b"strong-password-123"

        save_secret_key(keypair, sk_path, password=password)
        assert sk_path.exists()
        assert sk_path.stat().st_size > 0

        recovered = load_secret_key(sk_path, password=password)
        assert recovered == keypair.secret_key

    def test_load_secret_key_wrong_password(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        sk_path = tmp_path / "private.key"  # type: ignore[operator]
        keypair = _fresh_keypair(SecurityLevel.ML_KEM_768)

        save_secret_key(keypair, sk_path, password=b"correct")
        with pytest.raises(DecryptionError):
            load_secret_key(sk_path, password=b"WRONG")

    def test_load_public_key_autodetect_format(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """load_public_key debe detectar PEM vs JSON por la primera linea."""
        keypair = _fresh_keypair(SecurityLevel.ML_KEM_768)

        # PEM
        pem_path = tmp_path / "k.pem"  # type: ignore[operator]
        save_public_key(keypair, pem_path)
        assert load_public_key(pem_path, level=SecurityLevel.ML_KEM_768) == (
            keypair.public_key
        )

        # JSON
        json_path = tmp_path / "k.json"  # type: ignore[operator]
        save_public_key(keypair, json_path, fmt="json")
        assert load_public_key(json_path) == keypair.public_key


# ──────────────────────────────────────────────────────────────────────────
# Manejo de errores
# ──────────────────────────────────────────────────────────────────────────


class TestErrorHandling:
    """Formatos malformados deben lanzar KeySerializationError (no panic)."""

    def test_key_serialization_error_on_invalid_pem(self) -> None:
        from aegisq._aegisq_core import load_public_key_pem

        # PEM sin header
        with pytest.raises(KeySerializationError):
            load_public_key_pem("esto no es un PEM valido", SecurityLevel.ML_KEM_768)

        # PEM sin footer
        broken = f"{PEM_PUBLIC_HEADER}\nQUJDREVG\n"
        with pytest.raises(KeySerializationError):
            load_public_key_pem(broken, SecurityLevel.ML_KEM_768)

        # PEM con Base64 invalido en el cuerpo
        broken_b64 = f"{PEM_PUBLIC_HEADER}\n!!! no es base64 !!!\n{PEM_PUBLIC_FOOTER}\n"
        with pytest.raises(KeySerializationError):
            load_public_key_pem(broken_b64, SecurityLevel.ML_KEM_768)

    def test_key_serialization_error_on_truncated_blob(self) -> None:
        """Blob demasiado corto debe lanzar KeySerializationError."""
        truncated = b"AQPK" + b"\x01" * 5  # magic + 5 bytes, muy corto
        with pytest.raises(KeySerializationError):
            load_secret_key_raw(truncated, b"pwd")

        # Magic incorrecto
        bad_magic = b"XXXX" + b"\x00" * 100
        with pytest.raises(KeySerializationError):
            load_secret_key_raw(bad_magic, b"pwd")
