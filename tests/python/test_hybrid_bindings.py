"""Tests del bridge PyO3 para operaciones hibridas ML-KEM + AES-256-GCM.

Verifica que encrypt_hybrid y decrypt_hybrid funcionan correctamente
a traves del bridge Rust -> Python.
"""

import pytest

from aegisq._aegisq_core import (
    SecurityLevel,
    generate_keypair,
    encrypt_hybrid,
    decrypt_hybrid,
)
from aegisq.exceptions import (
    AegisQError,
    DecryptionError,
    InvalidParameterError,
)


class TestEncryptDecryptHybrid:
    """Tests para encrypt_hybrid y decrypt_hybrid."""

    @pytest.fixture()
    def keypair_768(self):
        return generate_keypair(SecurityLevel.ML_KEM_768)

    def test_roundtrip_768(self, keypair_768) -> None:
        plaintext = b"Hello, post-quantum world!"
        package = encrypt_hybrid(
            keypair_768.public_key, plaintext, SecurityLevel.ML_KEM_768
        )
        recovered = decrypt_hybrid(
            package, keypair_768.secret_key, SecurityLevel.ML_KEM_768
        )
        assert recovered == plaintext

    def test_roundtrip_all_levels(self) -> None:
        for level in [
            SecurityLevel.ML_KEM_512,
            SecurityLevel.ML_KEM_768,
            SecurityLevel.ML_KEM_1024,
        ]:
            kp = generate_keypair(level)
            plaintext = b"Testing all levels"
            package = encrypt_hybrid(kp.public_key, plaintext, level)
            recovered = decrypt_hybrid(package, kp.secret_key, level)
            assert recovered == plaintext, f"Roundtrip failed for {level}"

    def test_package_size(self, keypair_768) -> None:
        """Transit Package = capsule(1088) + nonce(12) + tag(16) + ciphertext(len)."""
        plaintext = b"Size test payload"
        package = encrypt_hybrid(
            keypair_768.public_key, plaintext, SecurityLevel.ML_KEM_768
        )
        expected = 1088 + 12 + 16 + len(plaintext)
        assert len(package) == expected

    def test_empty_plaintext(self, keypair_768) -> None:
        package = encrypt_hybrid(keypair_768.public_key, b"", SecurityLevel.ML_KEM_768)
        # overhead only (capsule + nonce + tag)
        assert len(package) == 1088 + 12 + 16
        recovered = decrypt_hybrid(
            package, keypair_768.secret_key, SecurityLevel.ML_KEM_768
        )
        assert recovered == b""

    def test_large_payload(self, keypair_768) -> None:
        plaintext = b"\x42" * 100_000  # 100 KB
        package = encrypt_hybrid(
            keypair_768.public_key, plaintext, SecurityLevel.ML_KEM_768
        )
        recovered = decrypt_hybrid(
            package, keypair_768.secret_key, SecurityLevel.ML_KEM_768
        )
        assert recovered == plaintext

    def test_returns_bytes(self, keypair_768) -> None:
        package = encrypt_hybrid(
            keypair_768.public_key, b"test", SecurityLevel.ML_KEM_768
        )
        assert isinstance(package, bytes)
        recovered = decrypt_hybrid(
            package, keypair_768.secret_key, SecurityLevel.ML_KEM_768
        )
        assert isinstance(recovered, bytes)

    def test_different_encryptions_produce_different_packages(
        self, keypair_768
    ) -> None:
        plaintext = b"Same plaintext"
        p1 = encrypt_hybrid(keypair_768.public_key, plaintext, SecurityLevel.ML_KEM_768)
        p2 = encrypt_hybrid(keypair_768.public_key, plaintext, SecurityLevel.ML_KEM_768)
        assert p1 != p2  # Different random KEM + nonce each time


class TestHybridErrorHandling:
    """Tests de manejo de errores en operaciones hibridas."""

    @pytest.fixture()
    def keypair_768(self):
        return generate_keypair(SecurityLevel.ML_KEM_768)

    def test_wrong_secret_key_raises_decryption_error(self) -> None:
        kp_alice = generate_keypair(SecurityLevel.ML_KEM_768)
        kp_bob = generate_keypair(SecurityLevel.ML_KEM_768)
        package = encrypt_hybrid(
            kp_alice.public_key, b"secret", SecurityLevel.ML_KEM_768
        )
        with pytest.raises(DecryptionError):
            decrypt_hybrid(package, kp_bob.secret_key, SecurityLevel.ML_KEM_768)

    def test_tampered_package_raises_decryption_error(self, keypair_768) -> None:
        package = encrypt_hybrid(
            keypair_768.public_key, b"tamper test", SecurityLevel.ML_KEM_768
        )
        tampered = bytearray(package)
        tampered[-1] ^= 0xFF  # Tamper last byte (ciphertext region)
        with pytest.raises(DecryptionError):
            decrypt_hybrid(
                bytes(tampered), keypair_768.secret_key, SecurityLevel.ML_KEM_768
            )

    def test_tampered_capsule_raises_decryption_error(self, keypair_768) -> None:
        """Tampered ML-KEM capsule -> implicit rejection -> wrong AES key -> tag fail."""
        package = encrypt_hybrid(
            keypair_768.public_key, b"capsule tamper", SecurityLevel.ML_KEM_768
        )
        tampered = bytearray(package)
        tampered[0] ^= 0xFF  # Tamper capsule
        with pytest.raises(DecryptionError):
            decrypt_hybrid(
                bytes(tampered), keypair_768.secret_key, SecurityLevel.ML_KEM_768
            )

    def test_package_too_small_raises_invalid_parameter(self, keypair_768) -> None:
        with pytest.raises(InvalidParameterError):
            decrypt_hybrid(
                b"too_small", keypair_768.secret_key, SecurityLevel.ML_KEM_768
            )

    def test_invalid_public_key_raises_invalid_parameter(self) -> None:
        with pytest.raises(InvalidParameterError):
            encrypt_hybrid(b"bad_pk", b"data", SecurityLevel.ML_KEM_768)

    def test_decryption_error_is_aegisq_error(self) -> None:
        """DecryptionError is a subclass of AegisQError."""
        kp = generate_keypair(SecurityLevel.ML_KEM_768)
        package = encrypt_hybrid(kp.public_key, b"test", SecurityLevel.ML_KEM_768)
        tampered = bytearray(package)
        tampered[-1] ^= 0xFF
        with pytest.raises(AegisQError):
            decrypt_hybrid(bytes(tampered), kp.secret_key, SecurityLevel.ML_KEM_768)
