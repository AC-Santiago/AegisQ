"""Regression tests for ML-KEM Implicit Rejection (FIPS 203 §7.3).

The FIPS 203 specification mandates that `ML-KEM.Decaps` MUST NOT return an
error when given an invalid ciphertext. Instead, it derives a
pseudo-random shared secret from internal material (specifically
`K̄ = SHAKE256(z || c̄)` where `z` is the rejection key embedded in `dk`
and `c̄` is a canonical re-encoding of the ciphertext).

This is a **critical** CCA2-security property: an attacker who can
distinguish "decryption succeeded with a real key" from "decryption
returned the rejection key" would gain an oracle they could use to
mount a chosen-ciphertext attack. By making the two paths
indistinguishable, FIPS 203 closes that oracle.

These tests are intentionally adversarial. They cover:

- Single-bit flips at every byte position of the capsule.
- Multi-byte tamperings (random XOR mask).
- All three security levels (ML-KEM-512 / 768 / 1024).
- Statistical independence: N distinct tamperings produce N distinct
  rejection secrets (no collisions, no pattern leakage).
- Determinism: same `(dk, tampered_capsule)` → same rejection secret.
- Path through `AegisCipher` (the hybrid KEM-DEM wrapper): a tampered
  Transit Package still never raises in the decapsulation step; AES-GCM
  tag verification raises `DecryptionError` afterwards but that is a
  separate concern (see `test_cipher_api.py`).

If any of these tests fail, the security model is broken. Do not
silence them — fix the implementation.
"""

from __future__ import annotations

import os
import pytest

from aegisq import AegisCipher, MlKem, SecurityLevel


ALL_LEVELS = [
    SecurityLevel.ML_KEM_512,
    SecurityLevel.ML_KEM_768,
    SecurityLevel.ML_KEM_1024,
]


def _level_name(level: SecurityLevel) -> str:
    """Human-readable name for assertion messages.

    `SecurityLevel` is a PyO3 class without a `.name` attribute, so we
    match against the module constants explicitly.
    """
    if level == SecurityLevel.ML_KEM_512:
        return "ML_KEM_512"
    if level == SecurityLevel.ML_KEM_768:
        return "ML_KEM_768"
    if level == SecurityLevel.ML_KEM_1024:
        return "ML_KEM_1024"
    return repr(level)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def kem() -> MlKem:
    return MlKem()


@pytest.fixture
def valid_encapsulation(kem: MlKem):
    """Returns `(keypair, capsule, original_ss)` for the default security level."""
    kp = kem.generate_keypair()
    capsule, ss = kem.encapsulate(kp.public_key)
    return kp, capsule, ss


# ---------------------------------------------------------------------------
# Property 1: tampered capsule NEVER raises — returns 32 bytes
# ---------------------------------------------------------------------------


class TestTamperedCapsuleNeverRaises:
    """For ANY single-byte flip within the capsule, decapsulate must:
    - not raise any Python exception
    - return exactly 32 bytes
    - return a value different from the original shared secret
    """

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_flip_every_byte_position(self, level: SecurityLevel) -> None:
        """Flip a single bit at every byte position of the capsule."""
        kem = MlKem(level=level)
        kp = kem.generate_keypair()
        capsule, original_ss = kem.encapsulate(kp.public_key)
        capsule_len = len(capsule)

        # Tamper at every byte position with a known mask.
        # Use 0xA5 so we exercise both high and low nibbles.
        for pos in range(capsule_len):
            tampered = bytearray(capsule)
            tampered[pos] ^= 0xA5

            # The critical property: must not raise.
            try:
                recovered = kem.decapsulate(bytes(tampered), kp.secret_key)
            except Exception as exc:  # noqa: BLE001
                pytest.fail(
                    f"decapsulate raised {type(exc).__name__} at tamper position "
                    f"{pos} of {capsule_len} (level={_level_name(level)}): {exc}"
                )

            # Output contract: 32 bytes.
            assert len(recovered) == 32, (
                f"rejection secret must be 32 bytes, got {len(recovered)} "
                f"at pos={pos} (level={_level_name(level)})"
            )

            # Pseudo-random: must differ from the legitimate shared secret.
            assert recovered != original_ss, (
                f"rejection secret must differ from original at pos={pos} "
                f"(level={_level_name(level)}) — implicit rejection broken"
            )


# ---------------------------------------------------------------------------
# Property 2: rejection outputs are statistically independent
# ---------------------------------------------------------------------------


class TestRejectionIndependence:
    """Different tamperings of the SAME ciphertext must yield DIFFERENT
    rejection secrets. If two distinct tamperings produced the same 32-byte
    output, an attacker could correlate tamperings to ciphertexts and
    weaken the CCA2 guarantee.
    """

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_many_random_tamperings_produce_unique_outputs(
        self, level: SecurityLevel
    ) -> None:
        kem = MlKem(level=level)
        kp = kem.generate_keypair()
        capsule, _original_ss = kem.encapsulate(kp.public_key)

        # 64 distinct tamperings = 4096 bit-pairs; plenty for collision check.
        # Birthday bound for 32-byte outputs: collisions in 64 samples
        # are vanishingly unlikely (< 1 in 2^224). A failure here means
        # the rejection function is not injective.
        n_samples = 64
        outputs: set[bytes] = set()

        for i in range(n_samples):
            tampered = bytearray(capsule)
            # XOR with a deterministic per-sample mask. Using os.urandom
            # would be fine but a deterministic seed makes regressions
            # easy to bisect. Multiply-then-mask keeps us inside 64 bits
            # so .to_bytes(8, ...) cannot OverflowError on later samples.
            mask = ((i + 1) * 0x9E3779B97F4A7C15 & 0xFFFFFFFFFFFFFFFF).to_bytes(
                8, "little"
            )
            for j in range(0, len(tampered) - 8, 8):
                for k in range(8):
                    tampered[j + k] ^= mask[k]

            recovered = kem.decapsulate(bytes(tampered), kp.secret_key)
            outputs.add(recovered)

        assert len(outputs) == n_samples, (
            f"expected {n_samples} distinct rejection secrets, got "
            f"{len(outputs)} (level={_level_name(level)}). Implicit rejection is "
            f"leaking information about the ciphertext."
        )


# ---------------------------------------------------------------------------
# Property 3: rejection is deterministic for the same input
# ---------------------------------------------------------------------------


class TestRejectionDeterminism:
    """Same `(dk, tampered_capsule)` MUST always produce the same rejection
    secret. Otherwise downstream code cannot rely on stable behavior across
    retries.
    """

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_repeated_decapsulation_is_stable(self, level: SecurityLevel) -> None:
        kem = MlKem(level=level)
        kp = kem.generate_keypair()
        capsule, _ = kem.encapsulate(kp.public_key)

        tampered = bytearray(capsule)
        tampered[0] ^= 0xFF
        tampered[-1] ^= 0xFF

        first = kem.decapsulate(bytes(tampered), kp.secret_key)
        for _ in range(10):
            again = kem.decapsulate(bytes(tampered), kp.secret_key)
            assert again == first, (
                "implicit rejection must be deterministic for the same "
                "(dk, c) pair — FIPS 203 §7.3"
            )


# ---------------------------------------------------------------------------
# Property 4: wrong key produces rejection (not raise)
# ---------------------------------------------------------------------------


class TestWrongSecretKey:
    """Decapsulating a real capsule with the WRONG secret key MUST NOT
    raise. The implementation must treat the situation as "ciphertext
    does not match this dk" and return the rejection key.
    """

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_wrong_key_returns_32_bytes(self, level: SecurityLevel) -> None:
        kem = MlKem(level=level)
        kp_a = kem.generate_keypair()
        kp_b = kem.generate_keypair()

        capsule, original_ss = kem.encapsulate(kp_a.public_key)

        try:
            recovered = kem.decapsulate(capsule, kp_b.secret_key)
        except Exception as exc:  # noqa: BLE001
            pytest.fail(
                f"decapsulate with wrong key raised {type(exc).__name__} "
                f"for {_level_name(level)}: {exc}"
            )

        assert len(recovered) == 32
        # Practically certain to differ; the probability of collision with
        # a random wrong-dk derivation is 2^-256.
        assert recovered != original_ss


# ---------------------------------------------------------------------------
# Property 5: AegisCipher path — decrypt_hybrid NEVER raises at the KEM step
# ---------------------------------------------------------------------------


class TestAegisCipherHybridTamper:
    """For the high-level API: a tampered Transit Package produces a
    fake AES key, which then fails AES-GCM tag verification. That is the
    EXPECTED behavior (tag verification must raise `DecryptionError`),
    but the KEM decapsulation inside `decrypt_hybrid` MUST NOT itself
    raise — implicit rejection runs first.

    We exercise this by inspecting the AegisCipher wrapper end-to-end
    and confirming that `DecryptionError` is the ONLY exception a
    tampered Transit Package can produce (never
    `DecapsulationError`, never any Rust panic translated to Python).
    """

    @pytest.mark.parametrize("level", ALL_LEVELS)
    def test_tampered_transit_package_raises_only_decryption_error(
        self, level: SecurityLevel
    ) -> None:
        from aegisq import DecryptionError

        sender = AegisCipher(level=level)
        receiver = AegisCipher(level=level)

        kp = receiver.generate_keypair()
        package = sender.encrypt(b"secret payload", kp.public_key)

        # Tamper with the FIRST byte (this is inside the KEM capsule,
        # before the nonce / tag / ciphertext).
        tampered = bytearray(package)
        tampered[0] ^= 0xFF

        with pytest.raises(DecryptionError):
            receiver.decrypt(bytes(tampered), kp.secret_key)