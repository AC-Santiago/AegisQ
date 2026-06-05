"""Tests de serializacion Base64 de llaves publicas ML-KEM.

Verifica el round-trip encode/decode para los tres niveles de seguridad,
y que los errores de formato y tamano se propagan correctamente.
"""

import base64 as _b64_stdlib
import math

import pytest

from aegisq import MlKem, SecurityLevel
from aegisq.exceptions import AegisQError


class TestPublicKeyB64RoundTrip:
    """Round-trip: serializar y deserializar debe recuperar los bytes originales."""

    @pytest.mark.parametrize(
        "level",
        [
            SecurityLevel.ML_KEM_512,
            SecurityLevel.ML_KEM_768,
            SecurityLevel.ML_KEM_1024,
        ],
    )
    def test_round_trip_all_levels(self, level: SecurityLevel) -> None:
        kem = MlKem(level=level)
        keypair = kem.generate_keypair()

        b64 = keypair.public_key_b64()
        assert isinstance(b64, str), "public_key_b64() debe devolver str"
        assert "=" not in b64, "Base64 URL-safe sin padding no debe contener '='"

        recovered = kem.load_public_key_b64(b64)
        assert recovered == keypair.public_key, (
            "Los bytes recuperados deben ser identicos a los originales"
        )

    def test_b64_is_url_safe(self) -> None:
        """Los caracteres '+' y '/' del Base64 estandar no deben aparecer."""
        kem = MlKem()
        keypair = kem.generate_keypair()
        b64 = keypair.public_key_b64()
        assert "+" not in b64, "Base64 URL-safe no debe contener '+'"
        assert "/" not in b64, "Base64 URL-safe no debe contener '/'"

    @pytest.mark.parametrize(
        "level, expected_pk_size",
        [
            (SecurityLevel.ML_KEM_512, 800),
            (SecurityLevel.ML_KEM_768, 1184),
            (SecurityLevel.ML_KEM_1024, 1568),
        ],
    )
    def test_b64_length_is_correct(
        self, level: SecurityLevel, expected_pk_size: int
    ) -> None:
        """El string Base64 debe tener la longitud correcta para el nivel."""
        # Se parametriza el tamano esperado en lugar de usar un dict con
        # SecurityLevel como key, porque SecurityLevel (PyO3 #[pyclass]
        # con eq_int) no es hashable como dict key de Python.
        # Base64 sin padding: ceil(n * 4 / 3) caracteres
        expected_b64_len = math.ceil(expected_pk_size * 4 / 3)

        kem = MlKem(level=level)
        keypair = kem.generate_keypair()
        b64 = keypair.public_key_b64()
        assert len(b64) == expected_b64_len


class TestPublicKeyB64ErrorHandling:
    """Errores de deserializacion deben lanzar AegisQError, nunca panic."""

    def test_invalid_base64_raises(self) -> None:
        kem = MlKem()
        with pytest.raises(AegisQError):
            kem.load_public_key_b64("esto-no-es-base64-valido!!!")

    def test_wrong_size_raises(self) -> None:
        """Bytes validos en Base64 pero de tamano incorrecto para el nivel."""
        kem = MlKem(level=SecurityLevel.ML_KEM_768)
        # Encodear solo 10 bytes — tamano incorrecto para ML-KEM-768
        short_b64 = _b64_stdlib.urlsafe_b64encode(b"shortkey12").rstrip(b"=").decode()
        with pytest.raises(AegisQError):
            kem.load_public_key_b64(short_b64)

    def test_empty_string_raises(self) -> None:
        kem = MlKem()
        with pytest.raises(AegisQError):
            kem.load_public_key_b64("")

    def test_cross_level_mismatch_raises(self) -> None:
        """Una llave de ML-KEM-512 no debe deserializarse como ML-KEM-768."""
        kem_512 = MlKem(level=SecurityLevel.ML_KEM_512)
        keypair_512 = kem_512.generate_keypair()
        b64_512 = keypair_512.public_key_b64()

        kem_768 = MlKem(level=SecurityLevel.ML_KEM_768)
        with pytest.raises(AegisQError):
            kem_768.load_public_key_b64(b64_512)
