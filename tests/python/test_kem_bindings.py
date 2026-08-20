"""Tests del bridge PyO3 para operaciones KEM crudas.

Verifica que las funciones generate_keypair, encapsulate y decapsulate
se exponen correctamente a Python desde Rust.
"""

import pytest

from aegisq._aegisq_core import (
    SecurityLevel,
    KeyPair,
    generate_keypair,
    encapsulate,
    decapsulate,
)
from aegisq.exceptions import (
    AegisQError,
    InvalidParameterError,
)


# --- SecurityLevel enum ---


class TestSecurityLevel:
    """Tests para el enum SecurityLevel."""

    def test_enum_values_exist(self) -> None:
        assert SecurityLevel.ML_KEM_512 is not None
        assert SecurityLevel.ML_KEM_768 is not None
        assert SecurityLevel.ML_KEM_1024 is not None

    def test_enum_equality(self) -> None:
        assert SecurityLevel.ML_KEM_768 == SecurityLevel.ML_KEM_768
        assert SecurityLevel.ML_KEM_512 != SecurityLevel.ML_KEM_768

    def test_enum_repr(self) -> None:
        r = repr(SecurityLevel.ML_KEM_768)
        assert "ML_KEM_768" in r


# --- generate_keypair ---


class TestGenerateKeypair:
    """Tests para la funcion generate_keypair."""

    def test_default_level(self) -> None:
        kp = generate_keypair()
        assert isinstance(kp, KeyPair)
        # Default is ML-KEM-768
        assert len(kp.public_key) == 1184
        assert len(kp.secret_key) == 2400

    def test_level_512(self) -> None:
        kp = generate_keypair(SecurityLevel.ML_KEM_512)
        assert len(kp.public_key) == 800
        assert len(kp.secret_key) == 1632
        assert kp.level == SecurityLevel.ML_KEM_512

    def test_level_768(self) -> None:
        kp = generate_keypair(SecurityLevel.ML_KEM_768)
        assert len(kp.public_key) == 1184
        assert len(kp.secret_key) == 2400
        assert kp.level == SecurityLevel.ML_KEM_768

    def test_level_1024(self) -> None:
        kp = generate_keypair(SecurityLevel.ML_KEM_1024)
        assert len(kp.public_key) == 1568
        assert len(kp.secret_key) == 3168
        assert kp.level == SecurityLevel.ML_KEM_1024

    def test_keys_are_bytes(self) -> None:
        kp = generate_keypair()
        assert isinstance(kp.public_key, bytes)
        assert isinstance(kp.secret_key, bytes)

    def test_different_keypairs_are_different(self) -> None:
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert kp1.public_key != kp2.public_key
        assert kp1.secret_key != kp2.secret_key

    def test_keypair_repr(self) -> None:
        kp = generate_keypair(SecurityLevel.ML_KEM_768)
        r = repr(kp)
        assert "KeyPair" in r
        # v1.4.0: el repr ya NO expone tamano de claves (informacion que
        # combinada con otra metadata facilita ataques de correlacion).
        # En su lugar muestra un fingerprint publico SHA3-256(pk)[:8].
        assert "fp=" in r
        import re
        assert re.search(r"fp=[0-9a-f]{16}", r) is not None
        # Tamano de claves NUNCA debe aparecer.
        assert "1184" not in r
        assert "2400" not in r


# --- encapsulate / decapsulate ---


class TestEncapsulateDecapsulate:
    """Tests para encapsulate y decapsulate."""

    @pytest.fixture()
    def keypair_768(self) -> KeyPair:
        return generate_keypair(SecurityLevel.ML_KEM_768)

    def test_roundtrip_768(self, keypair_768: KeyPair) -> None:
        capsule, shared_secret = encapsulate(
            keypair_768.public_key, SecurityLevel.ML_KEM_768
        )
        recovered = decapsulate(
            capsule, keypair_768.secret_key, SecurityLevel.ML_KEM_768
        )
        assert shared_secret == recovered

    def test_roundtrip_all_levels(self) -> None:
        for level in [
            SecurityLevel.ML_KEM_512,
            SecurityLevel.ML_KEM_768,
            SecurityLevel.ML_KEM_1024,
        ]:
            kp = generate_keypair(level)
            capsule, ss = encapsulate(kp.public_key, level)
            recovered = decapsulate(capsule, kp.secret_key, level)
            assert ss == recovered, f"Roundtrip failed for {level}"

    def test_shared_secret_size(self, keypair_768: KeyPair) -> None:
        _, shared_secret = encapsulate(keypair_768.public_key, SecurityLevel.ML_KEM_768)
        assert len(shared_secret) == 32

    def test_capsule_sizes(self) -> None:
        expected_sizes = [
            (SecurityLevel.ML_KEM_512, 768),
            (SecurityLevel.ML_KEM_768, 1088),
            (SecurityLevel.ML_KEM_1024, 1568),
        ]
        for level, expected in expected_sizes:
            kp = generate_keypair(level)
            capsule, _ = encapsulate(kp.public_key, level)
            assert len(capsule) == expected, f"Capsule size mismatch for {level}"

    def test_encapsulate_returns_bytes(self, keypair_768: KeyPair) -> None:
        capsule, ss = encapsulate(keypair_768.public_key, SecurityLevel.ML_KEM_768)
        assert isinstance(capsule, bytes)
        assert isinstance(ss, bytes)

    def test_decapsulate_returns_bytes(self, keypair_768: KeyPair) -> None:
        capsule, _ = encapsulate(keypair_768.public_key, SecurityLevel.ML_KEM_768)
        recovered = decapsulate(
            capsule, keypair_768.secret_key, SecurityLevel.ML_KEM_768
        )
        assert isinstance(recovered, bytes)

    def test_different_encapsulations_produce_different_secrets(
        self, keypair_768: KeyPair
    ) -> None:
        _, ss1 = encapsulate(keypair_768.public_key, SecurityLevel.ML_KEM_768)
        _, ss2 = encapsulate(keypair_768.public_key, SecurityLevel.ML_KEM_768)
        assert ss1 != ss2

    def test_implicit_rejection(self, keypair_768: KeyPair) -> None:
        """Decapsulate with tampered capsule returns a different (pseudorandom) secret."""
        capsule, original_ss = encapsulate(
            keypair_768.public_key, SecurityLevel.ML_KEM_768
        )
        # Tamper with capsule
        tampered = bytearray(capsule)
        tampered[0] ^= 0xFF
        tampered_capsule = bytes(tampered)

        # Should NOT raise — implicit rejection
        recovered = decapsulate(
            tampered_capsule, keypair_768.secret_key, SecurityLevel.ML_KEM_768
        )
        # Should return a different secret (not the original)
        assert recovered != original_ss
        assert len(recovered) == 32

    def test_invalid_public_key_size_raises(self) -> None:
        with pytest.raises(InvalidParameterError):
            encapsulate(b"too_short", SecurityLevel.ML_KEM_768)

    def test_invalid_secret_key_size_raises(self) -> None:
        kp = generate_keypair(SecurityLevel.ML_KEM_768)
        capsule, _ = encapsulate(kp.public_key, SecurityLevel.ML_KEM_768)
        with pytest.raises(InvalidParameterError):
            decapsulate(capsule, b"too_short", SecurityLevel.ML_KEM_768)

    def test_exception_hierarchy(self) -> None:
        """InvalidParameterError should be a subclass of AegisQError."""
        with pytest.raises(AegisQError):
            encapsulate(b"bad", SecurityLevel.ML_KEM_768)
