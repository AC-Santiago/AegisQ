"""Tests asincronos para AegisCipher.

Verifica que los metodos async encrypt_async y decrypt_async
funcionan correctamente sin bloquear el event loop.
"""

import asyncio

import pytest

from aegisq import AegisCipher, SecurityLevel
from aegisq.exceptions import DecryptionError, InvalidParameterError


class TestAegisCipherAsyncBasic:
    """Tests basicos de los metodos async."""

    @pytest.mark.asyncio
    async def test_async_encrypt_returns_bytes(self) -> None:
        """encrypt_async debe retornar bytes."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()

        package = await cipher.encrypt_async(
            plaintext=b"async test",
            recipient_public_key=kp.public_key,
        )
        assert isinstance(package, bytes)

    @pytest.mark.asyncio
    async def test_async_decrypt_returns_bytes(self) -> None:
        """decrypt_async debe retornar bytes."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        plaintext = b"async decrypt test"

        package = cipher.encrypt(
            plaintext=plaintext,
            recipient_public_key=kp.public_key,
        )
        recovered = await cipher.decrypt_async(
            encrypted_package=package,
            secret_key=kp.secret_key,
        )
        assert isinstance(recovered, bytes)

    @pytest.mark.asyncio
    async def test_async_roundtrip(self) -> None:
        """Roundtrip completo con metodos async."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        plaintext = b"Full async roundtrip"

        package = await cipher.encrypt_async(
            plaintext=plaintext,
            recipient_public_key=kp.public_key,
        )
        recovered = await cipher.decrypt_async(
            encrypted_package=package,
            secret_key=kp.secret_key,
        )

        assert recovered == plaintext


class TestAegisCipherAsyncAllLevels:
    """Tests async para todos los niveles de seguridad."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("level", [
        SecurityLevel.ML_KEM_512,
        SecurityLevel.ML_KEM_768,
        SecurityLevel.ML_KEM_1024,
    ])
    async def test_async_all_levels(self, level: SecurityLevel) -> None:
        """Verifica roundtrip async para los tres niveles."""
        cipher = AegisCipher(level=level)
        kp = cipher.generate_keypair()
        plaintext = b"Testing async level"

        package = await cipher.encrypt_async(
            plaintext=plaintext,
            recipient_public_key=kp.public_key,
        )
        recovered = await cipher.decrypt_async(
            encrypted_package=package,
            secret_key=kp.secret_key,
        )

        assert recovered == plaintext


class TestAegisCipherAsyncConcurrent:
    """Tests de ejecucion concurrente."""

    @pytest.mark.asyncio
    async def test_concurrent_encryption(self) -> None:
        """Multiples cifrados async concurrentes."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        messages = [f"Message {i}".encode() for i in range(10)]

        # Ejecutar todos los cifrados concurrentemente
        tasks = [
            cipher.encrypt_async(plaintext=msg, recipient_public_key=kp.public_key)
            for msg in messages
        ]
        packages = await asyncio.gather(*tasks)

        assert len(packages) == 10
        # Todos los paquetes deben ser distintos (nonce aleatorio)
        assert len(set(packages)) == 10

    @pytest.mark.asyncio
    async def test_concurrent_decryption(self) -> None:
        """Multiples descifrados async concurrentes."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        messages = [f"Concurrent message {i}".encode() for i in range(5)]

        # Cifrar todos sincronamente
        packages = [
            cipher.encrypt(plaintext=msg, recipient_public_key=kp.public_key)
            for msg in messages
        ]

        # Descifrar todos concurrentemente
        tasks = [
            cipher.decrypt_async(encrypted_package=pkg, secret_key=kp.secret_key)
            for pkg in packages
        ]
        recovered = await asyncio.gather(*tasks)

        assert recovered == messages


class TestAegisCipherAsyncMixed:
    """Tests de flujo mixto sync/async."""

    @pytest.mark.asyncio
    async def test_sync_encrypt_async_decrypt(self) -> None:
        """Cifrar sincronicamente, descifrar asincronicamente."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        plaintext = b"Mixed sync-async"

        package = cipher.encrypt(
            plaintext=plaintext,
            recipient_public_key=kp.public_key,
        )
        recovered = await cipher.decrypt_async(
            encrypted_package=package,
            secret_key=kp.secret_key,
        )

        assert recovered == plaintext

    @pytest.mark.asyncio
    async def test_async_encrypt_sync_decrypt(self) -> None:
        """Cifrar asincronicamente, descifrar sincronicamente."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        plaintext = b"Mixed async-sync"

        package = await cipher.encrypt_async(
            plaintext=plaintext,
            recipient_public_key=kp.public_key,
        )
        recovered = cipher.decrypt(
            encrypted_package=package,
            secret_key=kp.secret_key,
        )

        assert recovered == plaintext


class TestAegisCipherAsyncErrors:
    """Tests de manejo de errores en metodos async."""

    @pytest.mark.asyncio
    async def test_async_wrong_key_raises(self) -> None:
        """Clave incorrecta debe lanzar DecryptionError."""
        cipher = AegisCipher()
        kp_alice = cipher.generate_keypair()
        kp_bob = cipher.generate_keypair()

        package = cipher.encrypt(
            plaintext=b"Wrong key",
            recipient_public_key=kp_alice.public_key,
        )

        with pytest.raises(DecryptionError):
            await cipher.decrypt_async(
                encrypted_package=package,
                secret_key=kp_bob.secret_key,
            )

    @pytest.mark.asyncio
    async def test_async_tampered_package_raises(self) -> None:
        """Package manipulado debe lanzar DecryptionError."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()

        package = cipher.encrypt(
            plaintext=b"Tampered",
            recipient_public_key=kp.public_key,
        )
        tampered = bytearray(package)
        tampered[-1] ^= 0xFF

        with pytest.raises(DecryptionError):
            await cipher.decrypt_async(
                encrypted_package=bytes(tampered),
                secret_key=kp.secret_key,
            )

    @pytest.mark.asyncio
    async def test_async_invalid_public_key_raises(self) -> None:
        """Clave publica invalida debe lanzar InvalidParameterError."""
        cipher = AegisCipher()

        with pytest.raises(InvalidParameterError):
            await cipher.encrypt_async(
                plaintext=b"data",
                recipient_public_key=b"invalid_key",
            )


class TestAegisCipherAsyncEdgeCases:
    """Tests de casos limite."""

    @pytest.mark.asyncio
    async def test_async_empty_plaintext(self) -> None:
        """Plaintext vacio debe funcionar."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()

        package = await cipher.encrypt_async(
            plaintext=b"",
            recipient_public_key=kp.public_key,
        )
        recovered = await cipher.decrypt_async(
            encrypted_package=package,
            secret_key=kp.secret_key,
        )

        assert recovered == b""

    @pytest.mark.asyncio
    async def test_async_large_payload(self) -> None:
        """Payload grande (256 KB) debe funcionar."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        plaintext = bytes(range(256)) * 1000  # 256 KB

        package = await cipher.encrypt_async(
            plaintext=plaintext,
            recipient_public_key=kp.public_key,
        )
        recovered = await cipher.decrypt_async(
            encrypted_package=package,
            secret_key=kp.secret_key,
        )

        assert recovered == plaintext

    @pytest.mark.asyncio
    async def test_async_binary_data(self) -> None:
        """Datos binarios con bytes nulos deben funcionar."""
        cipher = AegisCipher()
        kp = cipher.generate_keypair()
        plaintext = b"\x00\x01\x02\xff\xfe\xfd" * 100

        package = await cipher.encrypt_async(
            plaintext=plaintext,
            recipient_public_key=kp.public_key,
        )
        recovered = await cipher.decrypt_async(
            encrypted_package=package,
            secret_key=kp.secret_key,
        )

        assert recovered == plaintext
