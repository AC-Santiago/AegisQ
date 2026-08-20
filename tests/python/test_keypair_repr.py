"""Tests del ``__repr__`` seguro de ``KeyPair``.

Sprint 2 task 6. ``KeyPair.__repr__`` debe mostrar solo el nivel de
seguridad y un fingerprint publico (primeros 8 bytes de SHA3-256
sobre la clave publica, hex-encodeados). Nunca debe filtrar bytes
crudos de la clave secreta ni de la clave publica.

Estos tests verifican:

1. Formato: ``KeyPair(level=<nivel>, fp=<16 hex>)``.
2. Determinismo: el mismo ``KeyPair`` produce siempre el mismo repr.
3. No-leaks: el repr NO contiene bytes de la clave secreta, ni
   bytes crudos de la clave publica, ni el Base64 de la misma.
4. Distinguibilidad: dos ``KeyPair`` distintos producen fingerprints
   distintos (con probabilidad negligible de colision: 2^-64).
5. Cobertura: el contrato se cumple para los 3 niveles de seguridad.

Si alguno falla, es un leak de material criptografico — fix
inmediato, no silenciar.
"""

from __future__ import annotations

import hashlib
import re

import pytest

from aegisq import AegisCipher, SecurityLevel


ALL_LEVELS = [
    SecurityLevel.ML_KEM_512,
    SecurityLevel.ML_KEM_768,
    SecurityLevel.ML_KEM_1024,
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _level_name(level: SecurityLevel) -> tuple[str, ...]:
    """Nombres aceptables del nivel en el repr.

    PyO3 expone el nivel con `#[pyo3(name = "ML_KEM_768")]`, pero el
    `{:?}` de Debug en el lado Rust sigue emitiendo el nombre interno
    `MlKem768`. Aceptamos ambos en el test.
    """
    if level == SecurityLevel.ML_KEM_512:
        return ("ML_KEM_512", "MlKem512")
    if level == SecurityLevel.ML_KEM_768:
        return ("ML_KEM_768", "MlKem768")
    if level == SecurityLevel.ML_KEM_1024:
        return ("ML_KEM_1024", "MlKem1024")
    return (repr(level),)


def _expected_fingerprint(public_key: bytes) -> str:
    """Primeros 8 bytes de SHA3-256(public_key), hex-encodeados."""
    digest = hashlib.sha3_256(public_key).digest()
    return digest[:8].hex()


# ---------------------------------------------------------------------------
# Formato
# ---------------------------------------------------------------------------


class TestReprFormat:
    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_repr_matches_expected_pattern(self, level: SecurityLevel) -> None:
        kp = AegisCipher(level=level).generate_keypair()
        rep = repr(kp)

        # El repr debe empezar con 'KeyPair(level='.
        assert rep.startswith("KeyPair(level="), rep
        # Y terminar con el fingerprint hex de 16 chars.
        assert rep.endswith(")"), rep
        # Debe contener alguno de los nombres aceptables del nivel
        # (ML_KEM_768 o MlKem768 segun el formato Debug del enum).
        assert any(name in rep for name in _level_name(level)), (
            f"expected level name {_level_name(level)} in repr: {rep}"
        )
        # Debe contener 'fp=' con un hex de 16 chars.
        match = re.search(r"fp=([0-9a-f]{16})", rep)
        assert match is not None, (
            f"expected 16-char hex fingerprint in repr: {rep}"
        )

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_fingerprint_matches_sha3_256_first_8_bytes(
        self, level: SecurityLevel
    ) -> None:
        """El fingerprint del repr debe coincidir con SHA3-256(pk)[:8] en hex."""
        kp = AegisCipher(level=level).generate_keypair()
        rep = repr(kp)

        match = re.search(r"fp=([0-9a-f]{16})", rep)
        assert match is not None
        fp_in_repr = match.group(1)

        expected = _expected_fingerprint(kp.public_key)
        assert fp_in_repr == expected, (
            f"fingerprint in repr ({fp_in_repr}) does not match "
            f"SHA3-256(pk)[:8] ({expected})"
        )


# ---------------------------------------------------------------------------
# Determinismo
# ---------------------------------------------------------------------------


class TestReprDeterminism:
    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_same_keypair_same_repr(self, level: SecurityLevel) -> None:
        kp = AegisCipher(level=level).generate_keypair()
        first = repr(kp)
        # Llamamos re() varias veces — el repr no debe mutar.
        for _ in range(5):
            assert repr(kp) == first

    def test_different_keypairs_different_fingerprints(self) -> None:
        kp_a = AegisCipher(level=SecurityLevel.ML_KEM_768).generate_keypair()
        kp_b = AegisCipher(level=SecurityLevel.ML_KEM_768).generate_keypair()
        # Probabilidad de colision: 2^-64 (8 bytes hex).
        assert repr(kp_a) != repr(kp_b)


# ---------------------------------------------------------------------------
# No-leaks de material criptografico
# ---------------------------------------------------------------------------


class TestReprDoesNotLeak:
    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_repr_does_not_contain_secret_key_bytes(
        self, level: SecurityLevel
    ) -> None:
        """El repr NO debe incluir ningun byte de la clave secreta."""
        kp = AegisCipher(level=level).generate_keypair()
        rep = repr(kp)

        sk_hex = kp.secret_key.hex()
        # Comprobamos que un prefijo largo (32 chars = 16 bytes) del
        # secret_key NO aparece en el repr. Suficiente para detectar
        # cualquier inclusion directa; un leak parcial seria visible en
        # logs incluso si fuera solo una fraccion.
        leak_prefix = sk_hex[:32]
        assert leak_prefix not in rep, (
            "secret_key bytes leaked into KeyPair.__repr__"
        )

        # Comprobacion adicional: el repr no contiene el secret_key en
        # base64 ni en ningun formato derivado (el tamano del sk es
        # publico, asi que excluimos tamano, pero NO bytes).
        # El tamano del sk varia por nivel: 1632, 2400, 3168. Ninguno
        # de esos deberia aparecer en el repr.
        for size in (1632, 2400, 3168):
            assert str(size) not in rep, (
                f"secret_key size {size} leaked into KeyPair.__repr__: {rep}"
            )

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_repr_does_not_contain_raw_public_key_bytes(
        self, level: SecurityLevel
    ) -> None:
        """El repr NO debe incluir bytes crudos de la clave publica.

        Solo se permite el fingerprint truncado (16 hex chars = 8 bytes).
        """
        kp = AegisCipher(level=level).generate_keypair()
        rep = repr(kp)

        pk_hex = kp.public_key.hex()
        # El prefijo de 32 chars (16 bytes) NO debe aparecer — el fp
        # solo son 16 chars, asi que cualquier string >16 hex de la pk
        # es leak.
        leak_prefix = pk_hex[:32]
        assert leak_prefix not in rep, (
            "public_key raw bytes leaked into KeyPair.__repr__"
        )

        # El fingerprint completo (16 chars) SI aparece — es el unico
        # material publico permitido. Lo extraemos y verificamos que
        # NO contiene los bytes adyacentes de la pk.
        match = re.search(r"fp=([0-9a-f]{16})", rep)
        assert match is not None
        fp_in_repr = match.group(1)
        # Los siguientes 16 chars del hex de la pk no deben aparecer en el repr
        next_pk_chars = pk_hex[16:32]
        assert next_pk_chars not in rep, (
            "public_key bytes beyond the 8-byte fingerprint leaked"
        )

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_repr_does_not_contain_base64_public_key(
        self, level: SecurityLevel
    ) -> None:
        """El repr NO debe incluir el Base64 URL-safe de la clave publica."""
        kp = AegisCipher(level=level).generate_keypair()
        rep = repr(kp)

        b64_pk = kp.public_key_b64()
        # Una fraccion significativa del base64 deberia bastar.
        assert b64_pk[:32] not in rep, (
            "base64 public_key leaked into KeyPair.__repr__"
        )

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_repr_does_not_contain_pem_or_json_serialization(
        self, level: SecurityLevel
    ) -> None:
        """El repr NO debe incluir las formas serializadas de la clave publica."""
        kp = AegisCipher(level=level).generate_keypair()
        rep = repr(kp)

        pem = kp.public_key_pem()
        json_form = kp.public_key_json()

        assert "BEGIN ML-KEM" not in rep, (
            "PEM header leaked into KeyPair.__repr__"
        )
        assert pem[:32] not in rep, (
            "PEM body leaked into KeyPair.__repr__"
        )
        assert "\"public_key\"" not in rep, (
            "JSON public_key field leaked into KeyPair.__repr__"
        )
        assert json_form[:32] not in rep, (
            "JSON body leaked into KeyPair.__repr__"
        )


# ---------------------------------------------------------------------------
# Tamano y tamano maximo del repr
# ---------------------------------------------------------------------------


class TestReprSize:
    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_repr_length_is_bounded(self, level: SecurityLevel) -> None:
        """El repr no debe contener cientos de bytes (indicativo de leak)."""
        kp = AegisCipher(level=level).generate_keypair()
        rep = repr(kp)
        # 'KeyPair(level=ML_KEM_XXX, fp=<16 hex>)' ~ 40 chars como mucho.
        assert len(rep) < 80, (
            f"repr suspiciously long ({len(rep)} chars): {rep}"
        )