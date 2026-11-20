import base64
import unittest

from descry.ciphers import caesar, xor
from descry.encodings import decode, detect

PLAIN = (
    "The quick brown fox jumps over the lazy dog. This is a normal English "
    "sentence with enough words to score well. "
)


class DecoderTests(unittest.TestCase):
    def test_individual_decoders(self) -> None:
        text = "Hello World"
        cases = [
            ("base64", base64.b64encode(text.encode()).decode(), text),
            ("base32", base64.b32encode(text.encode()).decode(), text),
            ("hex", text.encode().hex(), text),
            ("binary", " ".join(f"{byte:08b}" for byte in text.encode()), text),
            ("url", "%48%65%6c%6c%6f%20%57%6f%72%6c%64", text),
            (
                "morse",
                ".... . .-.. .-.. --- / .-- --- .-. .-.. -..",
                "hello world",
            ),
        ]
        decoders = {
            "base64": decode.decode_base64,
            "base32": decode.decode_base32,
            "hex": decode.decode_hex,
            "binary": decode.decode_binary,
            "url": decode.decode_url,
            "morse": decode.decode_morse,
        }
        for name, encoded, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(decoders[name](encoded), expected)

    def test_peel_layered_encodings(self) -> None:
        plaintext = "hello world"
        rotated = decode.rot13(plaintext)
        layered = base64.b64encode(rotated.encode().hex().encode()).decode()
        final, steps = decode.peel(layered)
        self.assertEqual(final, plaintext)
        self.assertEqual(steps, ["base64", "hex", "rot13"])

    def test_peel_leaves_plain_text_alone(self) -> None:
        final, steps = decode.peel("hello world")
        self.assertEqual(final, "hello world")
        self.assertEqual(steps, [])


class DetectTests(unittest.TestCase):
    def test_identifies_common_inputs(self) -> None:
        cases = [
            ("S2hvb3IgWnJ1b2c=", "base64"),
            ("Khoor Zruog", "caesar shift 3"),
            ("48656c6c6f", "hex"),
            ("01001000 01100101 01101100 01101100 01101111", "binary"),
            ("%48%65%6c%6c%6f", "url-encoding"),
            (
                ".... . .-.. .-.. --- / .-- --- .-. .-.. -..",
                "morse",
            ),
        ]
        for text, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(detect.detect(text)[0].label, expected)

    def test_identifies_single_byte_xor(self) -> None:
        ciphertext = xor.encrypt(PLAIN.encode() * 2, b"\x42").hex()
        self.assertEqual(detect.detect(ciphertext)[0].label, "single-byte xor 0x42")

    def test_crack_all_finds_plaintext_behind_encodings(self) -> None:
        caesar_text = caesar.encrypt(PLAIN, 3)
        encoded = base64.b64encode(caesar_text.encode()).decode()
        self.assertEqual(detect.crack_all("Khoor Zruog")[0].text, "Hello World")
        self.assertEqual(detect.crack_all(encoded)[0].text.strip(), PLAIN.strip())

    def test_crack_all_handles_xor_hex(self) -> None:
        plaintext = PLAIN.encode() * 2
        ciphertext = xor.encrypt(plaintext, b"\x42").hex()
        best = detect.crack_all(ciphertext)[0]
        self.assertTrue(best.text.startswith("The quick brown fox"))
