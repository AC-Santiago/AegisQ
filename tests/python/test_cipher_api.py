"""Tests end-to-end de la clase AegisCipher.

Verifica que la API de alto nivel funciona correctamente
para el usuario final.
"""

import pytest

from aegisq import AegisCipher, SecurityLevel
from aegisq.exceptions import DecryptionError, InvalidParameterError


class TestAegisCipherBasic:
    """Tests basicos de AegisCipher."""

    def test_default_level(self) -> None:
        cipher = AegisCipher()
        assert cipher.level == SecurityLevel.ML_KEM_768

    def test_custom_level(self) -> None:
        cipher = AegisCipher(level=SecurityLevel.ML_KEM_512)
        assert cipher.level == SecurityLevel.ML_KEM_512

    def test_repr(self) -> None:
        cipher = AegisCipher(level=SecurityLevel.ML_KEM_768)
        r = repr(cipher)
        assert "AegisCipher" in r
        assert "ML_KEM_768" in r

    def test_generate_keypair(self) -> None:
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        assert isinstance(kp.public_key, bytes)
        assert isinstance(kp.secret_key, bytes)
        assert len(kp.public_key) == 1184
        assert len(kp.secret_key) == 2400


class TestAegisCipherEncryptDecrypt:
    """Tests de cifrado y descifrado con AegisCipher."""

    def test_roundtrip_default(self) -> None:
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        plaintext = b"Post-quantum encryption works!"

        package = cipher.encrypt(
            plaintext=plaintext, recipient_public_key=kp.public_key
        )
        recovered = cipher.decrypt(encrypted_package=package, secret_key=kp.secret_key)

        assert recovered == plaintext

    def test_roundtrip_all_levels(self) -> None:
        for level in [
            SecurityLevel.ML_KEM_512,
            SecurityLevel.ML_KEM_768,
            SecurityLevel.ML_KEM_1024,
        ]:
            cipher = AegisCipher(level=level)
            kp = cipher.generate_keypair()
            plaintext = b"Testing level roundtrip"

            package = cipher.encrypt(
                plaintext=plaintext, recipient_public_key=kp.public_key
            )
            recovered = cipher.decrypt(
                encrypted_package=package, secret_key=kp.secret_key
            )

            assert recovered == plaintext, f"Roundtrip failed for {level}"

    def test_empty_plaintext(self) -> None:
        cipher = AegisCipher()
        kp = cipher.generate_keypair()

        package = cipher.encrypt(plaintext=b"", recipient_public_key=kp.public_key)
        recovered = cipher.decrypt(encrypted_package=package, secret_key=kp.secret_key)

        assert recovered == b""

    def test_large_payload(self) -> None:
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        plaintext = bytes(range(256)) * 1000  # 256 KB

        package = cipher.encrypt(
            plaintext=plaintext, recipient_public_key=kp.public_key
        )
        recovered = cipher.decrypt(encrypted_package=package, secret_key=kp.secret_key)

        assert recovered == plaintext

    def test_binary_data(self) -> None:
        """Test with arbitrary binary data including null bytes."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        plaintext = b"\x00\x01\x02\xff\xfe\xfd" * 100

        package = cipher.encrypt(
            plaintext=plaintext, recipient_public_key=kp.public_key
        )
        recovered = cipher.decrypt(encrypted_package=package, secret_key=kp.secret_key)

        assert recovered == plaintext

    def test_encrypt_returns_bytes(self) -> None:
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        package = cipher.encrypt(plaintext=b"test", recipient_public_key=kp.public_key)
        assert isinstance(package, bytes)

    def test_decrypt_returns_bytes(self) -> None:
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        package = cipher.encrypt(plaintext=b"test", recipient_public_key=kp.public_key)
        recovered = cipher.decrypt(encrypted_package=package, secret_key=kp.secret_key)
        assert isinstance(recovered, bytes)

    def test_package_size(self) -> None:
        """Verify Transit Package size: capsule + nonce(12) + tag(16) + ciphertext."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        plaintext = b"Size check"

        package = cipher.encrypt(
            plaintext=plaintext, recipient_public_key=kp.public_key
        )
        expected_overhead = 1088 + 12 + 16  # ML-KEM-768 capsule + nonce + tag
        assert len(package) == expected_overhead + len(plaintext)

    def test_different_encryptions_produce_different_packages(self) -> None:
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        plaintext = b"Same data, different packages"

        p1 = cipher.encrypt(plaintext=plaintext, recipient_public_key=kp.public_key)
        p2 = cipher.encrypt(plaintext=plaintext, recipient_public_key=kp.public_key)

        assert p1 != p2

    def test_alice_bob_flow(self) -> None:
        """Test the canonical Alice -> Bob flow from AGENTS.md."""
        # Bob generates keypair
        cipher_bob = AegisCipher(level=SecurityLevel.ML_KEM_768)
        keypair = cipher_bob.generate_keypair()

        # Alice encrypts
        cipher_alice = AegisCipher(level=SecurityLevel.ML_KEM_768)
        package = cipher_alice.encrypt(
            plaintext=b"Datos secretos",
            recipient_public_key=keypair.public_key,
        )

        # Bob decrypts
        plaintext = cipher_bob.decrypt(
            encrypted_package=package,
            secret_key=keypair.secret_key,
        )

        assert plaintext == b"Datos secretos"

    def test_multiple_messages_same_keypair(self) -> None:
        """Multiple messages can be encrypted/decrypted with the same keypair."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()

        messages = [b"Message 1", b"Message 2", b"Message 3", b"" * 0, b"\x00" * 1000]

        for msg in messages:
            package = cipher.encrypt(plaintext=msg, recipient_public_key=kp.public_key)
            recovered = cipher.decrypt(
                encrypted_package=package, secret_key=kp.secret_key
            )
            assert recovered == msg


class TestAegisCipherErrors:
    """Tests de manejo de errores de AegisCipher."""

    def test_wrong_key_raises_decryption_error(self) -> None:
        cipher = AegisCipher()
        kp_alice = cipher.generate_keypair()
        kp_bob = cipher.generate_keypair()

        package = cipher.encrypt(
            plaintext=b"Wrong key test", recipient_public_key=kp_alice.public_key
        )

        with pytest.raises(DecryptionError):
            cipher.decrypt(encrypted_package=package, secret_key=kp_bob.secret_key)

    def test_tampered_package_raises_decryption_error(self) -> None:
        cipher = AegisCipher()
        kp = cipher.generate_keypair()

        package = cipher.encrypt(
            plaintext=b"Tamper test", recipient_public_key=kp.public_key
        )
        tampered = bytearray(package)
        tampered[-1] ^= 0xFF
        tampered_package = bytes(tampered)

        with pytest.raises(DecryptionError):
            cipher.decrypt(encrypted_package=tampered_package, secret_key=kp.secret_key)

    def test_invalid_public_key_raises(self) -> None:
        cipher = AegisCipher()
        with pytest.raises(InvalidParameterError):
            cipher.encrypt(plaintext=b"data", recipient_public_key=b"not_a_valid_key")

    def test_package_too_small_raises(self) -> None:
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        with pytest.raises(InvalidParameterError):
            cipher.decrypt(encrypted_package=b"tiny", secret_key=kp.secret_key)
