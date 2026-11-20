from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT)
    environment["PYTHONIOENCODING"] = "utf-8"
    environment.pop("NO_COLOR", None)
    return subprocess.run(
        [sys.executable, "-m", "descry", *args],
        cwd=ROOT,
        input=input_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
        timeout=60,
    )


class CliTests(unittest.TestCase):
    def test_crack_json(self) -> None:
        result = run_cli("crack", "Khoor Zruog", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload[0]["key"], "caesar shift 3")
        self.assertEqual(payload[0]["text"], "Hello World")

    def test_stdin_and_plain_output(self) -> None:
        result = run_cli("caesar", "dec", "--shift", "3", input_text="Khoor Zruog\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "Hello World")
        self.assertNotIn("\x1b[", result.stdout)

    def test_id_json(self) -> None:
        result = run_cli("id", "S2hvb3IgWnJ1b2c=", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)[0]["key"], "base64")

    def test_decode_json(self) -> None:
        result = run_cli("decode", "SGVsbG8gV29ybGQ=", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["output"], "Hello World")
        self.assertEqual(payload["steps"], ["base64"])

    def test_cipher_round_trips_through_cli(self) -> None:
        caesar_result = run_cli("caesar", "enc", "Hello World", "--shift", "3", "--format", "json")
        self.assertEqual(json.loads(caesar_result.stdout)["text"], "Khoor Zruog")

        vigenere_result = run_cli(
            "vigenere", "enc", "Attack at dawn", "--key", "LEMON", "--format", "json"
        )
        ciphertext = json.loads(vigenere_result.stdout)["text"]
        decrypted = run_cli("vigenere", "dec", ciphertext, "--key", "LEMON")
        self.assertEqual(decrypted.stdout.strip(), "Attack at dawn")

        xor_result = run_cli("xor", "enc", "secret", "--key", "key", "--format", "json")
        ciphertext_hex = json.loads(xor_result.stdout)["hex"]
        plaintext = run_cli("xor", "dec", ciphertext_hex, "--key", "key")
        self.assertEqual(plaintext.stdout.strip(), "secret")

    def test_xor_crack_from_stdin(self) -> None:
        from descry.ciphers import xor

        ciphertext = xor.encrypt(b"The secret message is hidden here. " * 3, b"\x42").hex()
        result = run_cli("xor", "crack", "--format", "json", "--top", "1", input_text=ciphertext)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload[0]["key"], "0x42")
        self.assertTrue(payload[0]["text"].startswith("The secret message"))

    def test_freq_json(self) -> None:
        result = run_cli("freq", "The quick brown fox", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["summary"]["letters"], 16)
        self.assertIn("index_of_coincidence", payload["summary"])

    def test_low_confidence_exit_code(self) -> None:
        result = run_cli("crack", "qzxv qzxv qzxv", "--threshold", "99")
        self.assertEqual(result.returncode, 1)

    def test_user_errors_are_clean(self) -> None:
        shift = run_cli("caesar", "enc", "hello", "--shift", "26")
        self.assertEqual(shift.returncode, 2)
        self.assertIn("shift must be between 0 and 25", shift.stderr)
        self.assertNotIn("Traceback", shift.stderr)

        missing = run_cli("crack", "-f", "does-not-exist.txt")
        self.assertEqual(missing.returncode, 2)
        self.assertIn("cannot read", missing.stderr)
        self.assertNotIn("Traceback", missing.stderr)

    def test_help_has_examples(self) -> None:
        result = run_cli("caesar", "enc", "-h")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Examples:", result.stdout)
        self.assertIn("descry caesar enc", result.stdout)

    def test_no_arguments_shows_grouped_commands(self) -> None:
        result = run_cli()
        self.assertEqual(result.returncode, 0)
        self.assertIn("CRACKING", result.stdout)
        self.assertIn("vigenere", result.stdout)
