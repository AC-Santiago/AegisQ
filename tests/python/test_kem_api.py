"""Tests de la API Python MlKem.

Verifica que la clase MlKem expone correctamente las operaciones ML-KEM
de bajo nivel y que el roundtrip encapsulate/decapsulate funciona.
"""

import pytest

from aegisq import MlKem, SecurityLevel
from aegisq.exceptions import InvalidParameterError


class TestMlKemBasic:
    """Tests basicos de la clase MlKem."""

    def test_default_level(self) -> None:
        kem = MlKem()
        assert kem.level == SecurityLevel.ML_KEM_768

    def test_custom_level(self) -> None:
        kem = MlKem(level=SecurityLevel.ML_KEM_512)
        assert kem.level == SecurityLevel.ML_KEM_512

    def test_repr(self) -> None:
        kem = MlKem(level=SecurityLevel.ML_KEM_1024)
        r = repr(kem)
        assert "MlKem" in r
        assert "ML_KEM_1024" in r

    def test_generate_keypair(self) -> None:
        kem = MlKem()
        kp = kem.generate_keypair()
        assert isinstance(kp.public_key, bytes)
        assert isinstance(kp.secret_key, bytes)
        assert len(kp.public_key) == 1184
        assert len(kp.secret_key) == 2400


class TestMlKemRoundtrip:
    """Tests de roundtrip encapsulate/decapsulate."""

    def test_roundtrip_768(self) -> None:
        kem = MlKem(level=SecurityLevel.ML_KEM_768)
        kp = kem.generate_keypair()

        capsule, shared_secret = kem.encapsulate(kp.public_key)
        recovered = kem.decapsulate(capsule, kp.secret_key)

        assert shared_secret == recovered

    def test_roundtrip_all_levels(self) -> None:
        for level in [
            SecurityLevel.ML_KEM_512,
            SecurityLevel.ML_KEM_768,
            SecurityLevel.ML_KEM_1024,
        ]:
            kem = MlKem(level=level)
            kp = kem.generate_keypair()
            capsule, ss = kem.encapsulate(kp.public_key)
            recovered = kem.decapsulate(capsule, kp.secret_key)
            assert ss == recovered, f"Roundtrip failed for {level}"

    def test_shared_secret_is_32_bytes(self) -> None:
        kem = MlKem()
        kp = kem.generate_keypair()
        _, shared_secret = kem.encapsulate(kp.public_key)
        assert len(shared_secret) == 32

    def test_encapsulate_returns_bytes_tuple(self) -> None:
        kem = MlKem()
        kp = kem.generate_keypair()
        capsule, ss = kem.encapsulate(kp.public_key)
        assert isinstance(capsule, bytes)
        assert isinstance(ss, bytes)

    def test_decapsulate_returns_bytes(self) -> None:
        kem = MlKem()
        kp = kem.generate_keypair()
        capsule, _ = kem.encapsulate(kp.public_key)
        recovered = kem.decapsulate(capsule, kp.secret_key)
        assert isinstance(recovered, bytes)

    def test_different_encapsulations_different_secrets(self) -> None:
        kem = MlKem()
        kp = kem.generate_keypair()
        _, ss1 = kem.encapsulate(kp.public_key)
        _, ss2 = kem.encapsulate(kp.public_key)
        assert ss1 != ss2

    def test_multiple_roundtrips_same_keypair(self) -> None:
        kem = MlKem()
        kp = kem.generate_keypair()

        for _ in range(5):
            capsule, ss = kem.encapsulate(kp.public_key)
            recovered = kem.decapsulate(capsule, kp.secret_key)
            assert ss == recovered


class TestMlKemImplicitRejection:
    """Tests de implicit rejection (FIPS 203 §7.3)."""

    def test_tampered_capsule_returns_different_secret(self) -> None:
        """Tampered capsule does NOT raise — returns pseudorandom secret instead."""
        kem = MlKem()
        kp = kem.generate_keypair()
        capsule, original_ss = kem.encapsulate(kp.public_key)

        tampered = bytearray(capsule)
        tampered[0] ^= 0xFF
        tampered_capsule = bytes(tampered)

        # Should NOT raise
        recovered = kem.decapsulate(tampered_capsule, kp.secret_key)

        # Should be different from original
        assert recovered != original_ss
        assert len(recovered) == 32

    def test_wrong_key_returns_different_secret(self) -> None:
        """Using wrong secret key returns a different secret (not an error)."""
        kem = MlKem()
        kp1 = kem.generate_keypair()
        kp2 = kem.generate_keypair()

        capsule, original_ss = kem.encapsulate(kp1.public_key)

        # Decapsulate with wrong key — should NOT raise
        recovered = kem.decapsulate(capsule, kp2.secret_key)
        assert recovered != original_ss
        assert len(recovered) == 32


class TestMlKemErrors:
    """Tests de manejo de errores."""

    def test_invalid_public_key_size(self) -> None:
        kem = MlKem()
        with pytest.raises(InvalidParameterError):
            kem.encapsulate(b"too_short")

    def test_invalid_secret_key_size(self) -> None:
        kem = MlKem()
        kp = kem.generate_keypair()
        capsule, _ = kem.encapsulate(kp.public_key)
        with pytest.raises(InvalidParameterError):
            kem.decapsulate(capsule, b"too_short")
