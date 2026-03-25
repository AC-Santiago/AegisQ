"""Tests de validacion con vectores KAT del NIST ACVP.

Este test valida la implementacion de ML-KEM contra los vectores
oficiales publicados por el NIST en:
https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files

Los vectores KAT (Known Answer Tests) verifican que la implementacion
produce exactamente los mismos resultados que la referencia del NIST.

IMPORTANT: Las funciones deterministas (generate_keypair_deterministic,
encapsulate_deterministic) son SOLO para testing. NO usar en produccion.
"""

import json
import pytest
from pathlib import Path

from aegisq._aegisq_core import (
    SecurityLevel,
    generate_keypair_deterministic,
    encapsulate_deterministic,
)


# Rutas a los archivos JSON con vectores KAT
KAT_DIR = Path(__file__).parent / "json-files"

# Tamannos esperados por nivel (definidos en FIPS 203)
SECURITY_LEVEL_SIZES = {
    "ML_KEM_512": {
        "public_key": 800,
        "secret_key": 1632,
        "capsule": 768,
    },
    "ML_KEM_768": {
        "public_key": 1184,
        "secret_key": 2400,
        "capsule": 1088,
    },
    "ML_KEM_1024": {
        "public_key": 1568,
        "secret_key": 3168,
        "capsule": 1568,
    },
}

# Mapeo de nivel NIST a SecurityLevel
NIST_TO_SECURITY_LEVEL = {
    "ML-KEM-512": SecurityLevel.ML_KEM_512,
    "ML-KEM-768": SecurityLevel.ML_KEM_768,
    "ML-KEM-1024": SecurityLevel.ML_KEM_1024,
}


def hex_to_bytes(hex_str: str) -> bytes:
    """Convierte string hexadecimal a bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convierte bytes a string hexadecimal (uppercase)."""
    return data.hex().upper()


class TestKeyGenVectors:
    """Tests de validacion para ML-KEM KeyGen."""

    @pytest.fixture
    def keygen_vectors(self):
        """Carga los vectores KeyGen desde JSON."""
        internal_file = KAT_DIR / "ML-KEM-keyGen-FIPS203" / "internalProjection.json"
        with open(internal_file, "r") as f:
            return json.load(f)

    @pytest.mark.parametrize(
        "parameter_set", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    )
    def test_keygen_vectors(self, keygen_vectors, parameter_set):
        """Valida que generate_keypair_deterministic produce los resultados esperados."""
        level = NIST_TO_SECURITY_LEVEL[parameter_set]

        # Buscar el grupo de tests para este nivel
        for group in keygen_vectors["testGroups"]:
            if group.get("parameterSet") == parameter_set:
                test_cases = group["tests"]
                break
        else:
            pytest.fail(f"No se encontraron vectores para {parameter_set}")

        failed_cases = []

        for test_case in test_cases:
            tc_id = test_case["tcId"]
            z = hex_to_bytes(test_case["z"])
            d = hex_to_bytes(test_case["d"])
            expected_ek = hex_to_bytes(test_case["ek"])
            expected_dk = hex_to_bytes(test_case["dk"])

            # Generar clave con seeds especificos
            keypair = generate_keypair_deterministic(d, z, level)

            # Verificar public key (ek)
            if keypair.public_key != expected_ek:
                failed_cases.append(
                    {
                        "tcId": tc_id,
                        "field": "ek",
                        "expected": bytes_to_hex(expected_ek),
                        "actual": bytes_to_hex(keypair.public_key),
                    }
                )

            # Verificar secret key (dk)
            if keypair.secret_key != expected_dk:
                failed_cases.append(
                    {
                        "tcId": tc_id,
                        "field": "dk",
                        "expected": bytes_to_hex(expected_dk),
                        "actual": bytes_to_hex(keypair.secret_key),
                    }
                )

        if failed_cases:
            failure_msg = f"KeyGen KAT fallidos para {parameter_set}:\n"
            for fc in failed_cases[:5]:  # Mostrar maximo 5 fallos
                failure_msg += f"  tcId={fc['tcId']}, field={fc['field']}\n"
                failure_msg += f"    expected: {fc['expected'][:64]}...\n"
                failure_msg += f"    actual:   {fc['actual'][:64]}...\n"
            pytest.fail(failure_msg)


class TestEncapDecapVectors:
    """Tests de validacion para ML-KEM Encap/Decap."""

    @pytest.fixture
    def encap_vectors(self):
        """Carga los vectores Encap/Decap desde JSON."""
        internal_file = (
            KAT_DIR / "ML-KEM-encapDecap-FIPS203" / "internalProjection.json"
        )
        with open(internal_file, "r") as f:
            return json.load(f)

    @pytest.mark.parametrize(
        "parameter_set", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    )
    def test_encapsulation_vectors(self, encap_vectors, parameter_set):
        """Valida que encapsulate_deterministic produce los resultados esperados."""
        level = NIST_TO_SECURITY_LEVEL[parameter_set]

        # Buscar el grupo de tests para encapsulacion
        for group in encap_vectors["testGroups"]:
            if group.get("parameterSet") == parameter_set:
                if group.get("function") != "encapsulation":
                    continue
                test_cases = group["tests"]
                break
        else:
            pytest.skip(
                f"No se encontraron vectores de encapsulacion para {parameter_set}"
            )

        failed_cases = []

        for test_case in test_cases:
            tc_id = test_case["tcId"]
            ek = hex_to_bytes(test_case["ek"])
            m = hex_to_bytes(test_case["m"])
            expected_c = hex_to_bytes(test_case["c"])
            expected_k = hex_to_bytes(test_case["k"])

            # Encapsular con mensaje especifico
            capsule, shared_secret, returned_m = encapsulate_deterministic(ek, m, level)

            # Verificar capsule (c)
            if capsule != expected_c:
                failed_cases.append(
                    {
                        "tcId": tc_id,
                        "field": "c",
                        "expected": bytes_to_hex(expected_c),
                        "actual": bytes_to_hex(capsule),
                    }
                )

            # Verificar shared secret (k)
            if shared_secret != expected_k:
                failed_cases.append(
                    {
                        "tcId": tc_id,
                        "field": "k",
                        "expected": bytes_to_hex(expected_k),
                        "actual": bytes_to_hex(shared_secret),
                    }
                )

            # Verificar que m se devuelve correctamente
            if returned_m != m:
                failed_cases.append(
                    {
                        "tcId": tc_id,
                        "field": "m",
                        "expected": bytes_to_hex(m),
                        "actual": bytes_to_hex(returned_m),
                    }
                )

        if failed_cases:
            failure_msg = f"Encap KAT fallidos para {parameter_set}:\n"
            for fc in failed_cases[:5]:  # Mostrar maximo 5 fallos
                failure_msg += f"  tcId={fc['tcId']}, field={fc['field']}\n"
                failure_msg += f"    expected: {fc['expected'][:64]}...\n"
                failure_msg += f"    actual:   {fc['actual'][:64]}...\n"
            pytest.fail(failure_msg)


class TestDeterministicAPIContract:
    """Tests del contrato de la API determinista."""

    def test_keygen_seed_size_validation(self):
        """Verifica que se rechacen seeds de tamano incorrecto."""
        with pytest.raises(Exception):  # InvalidParameterError
            generate_keypair_deterministic(
                b"short",  # Solo 5 bytes
                b"0" * 32,
                SecurityLevel.ML_KEM_768,
            )

        with pytest.raises(Exception):
            generate_keypair_deterministic(
                b"0" * 32,
                b"short",  # Solo 5 bytes
                SecurityLevel.ML_KEM_768,
            )

    def test_encaps_message_size_validation(self):
        """Verifica que se rechace mensaje de tamano incorrecto."""
        keypair = generate_keypair_deterministic(
            b"0" * 32, b"0" * 32, SecurityLevel.ML_KEM_768
        )

        with pytest.raises(Exception):  # InvalidParameterError
            encapsulate_deterministic(
                keypair.public_key,
                b"short",  # Solo 5 bytes
                SecurityLevel.ML_KEM_768,
            )

    def test_all_security_levels_deterministic(self):
        """Verifica que todos los niveles funcionen."""
        d = b"D" * 32
        z = b"Z" * 32
        m = b"M" * 32

        levels = [
            (SecurityLevel.ML_KEM_512, "ML_KEM_512"),
            (SecurityLevel.ML_KEM_768, "ML_KEM_768"),
            (SecurityLevel.ML_KEM_1024, "ML_KEM_1024"),
        ]

        for level, level_name in levels:
            keypair = generate_keypair_deterministic(d, z, level)
            capsule, ss, returned_m = encapsulate_deterministic(
                keypair.public_key, m, level
            )

            sizes = SECURITY_LEVEL_SIZES[level_name]
            assert len(keypair.public_key) == sizes["public_key"]
            assert len(keypair.secret_key) == sizes["secret_key"]
            assert len(capsule) == sizes["capsule"]
            assert len(ss) == 32
            assert returned_m == m


class TestVectorStructureValidation:
    """Tests de validacion de la estructura de los vectores."""

    def test_keygen_internal_projection_structure(self):
        """Verifica estructura del JSON de KeyGen."""
        internal_file = KAT_DIR / "ML-KEM-keyGen-FIPS203" / "internalProjection.json"
        with open(internal_file, "r") as f:
            data = json.load(f)

        assert "testGroups" in data
        for group in data["testGroups"]:
            assert "parameterSet" in group
            assert group["parameterSet"] in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
            for test in group["tests"]:
                assert "tcId" in test
                assert "z" in test
                assert "d" in test
                assert "ek" in test
                assert "dk" in test
                # Verificar tamano de seeds (32 bytes = 64 hex chars)
                assert len(test["z"]) == 64
                assert len(test["d"]) == 64

    def test_encapdec_internal_projection_structure(self):
        """Verifica estructura del JSON de Encap/Decap."""
        internal_file = (
            KAT_DIR / "ML-KEM-encapDecap-FIPS203" / "internalProjection.json"
        )
        with open(internal_file, "r") as f:
            data = json.load(f)

        assert "testGroups" in data
        for group in data["testGroups"]:
            assert "parameterSet" in group
            assert "function" in group
            for test in group["tests"]:
                assert "tcId" in test
                # Los vectores pueden tener diferentes estructuras segun el tipo de test
                # (encapsulation vs decapsulation vs keyCheck)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
