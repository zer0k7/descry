import unittest

from descry.ciphers import caesar, vigenere, xor

PLAIN = (
    "The quick brown fox jumps over the lazy dog. This is a normal English "
    "sentence with enough words to score well. "
)


class CaesarTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        text = "Hello, World! Numbers 123 stay put."
        for shift in (0, 1, 3, 13, 25):
            with self.subTest(shift=shift):
                self.assertEqual(caesar.decrypt(caesar.encrypt(text, shift), shift), text)

    def test_brute_force_ranks_the_real_shift_first(self) -> None:
        ciphertext = caesar.encrypt(PLAIN * 4, 3)
        best = caesar.brute_force(ciphertext)[0]
        self.assertEqual(best.label, "shift 3")
        self.assertEqual(best.text, PLAIN * 4)


class VigenereTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        text = "Attack at dawn! Meet me at 09:00."
        for key in ("KEY", "lemon", "ABC"):
            with self.subTest(key=key):
                self.assertEqual(
                    vigenere.decrypt(vigenere.encrypt(text, key), key), text
                )

    def test_crack_recovers_key_and_plaintext(self) -> None:
        plaintext = PLAIN * 5
        ciphertext = vigenere.encrypt(plaintext, "LEMON")
        best = vigenere.crack(ciphertext)[0]
        self.assertEqual(best.label, "key LEMON")
        self.assertEqual(best.text, plaintext)

    def test_rejects_non_letter_key(self) -> None:
        with self.assertRaises(ValueError):
            vigenere.encrypt("text", "K3Y")


class XorTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        for data, key in [
            (b"secret", b"key"),
            (bytes(range(32)), b"\x00\x01"),
            ("unicode text".encode(), b"K"),
        ]:
            with self.subTest(key=key):
                self.assertEqual(xor.decrypt(xor.encrypt(data, key), key), data)

    def test_single_byte_crack(self) -> None:
        plaintext = PLAIN.encode() * 3
        ciphertext = xor.encrypt(plaintext, b"\x42")
        best = xor.single_byte_crack(ciphertext)[0]
        self.assertEqual(best.label, "0x42")
        self.assertEqual(best.text, plaintext.decode("latin-1"))

    def test_repeating_key_detection_and_recovery(self) -> None:
        plaintext = PLAIN.encode() * 4
        ciphertext = xor.encrypt(plaintext, b"KEY")
        self.assertEqual(xor.find_key_length(ciphertext), 3)
        best = xor.repeating_key_crack(ciphertext)[0]
        self.assertTrue(best.label.startswith("0x4b4559"))
        self.assertEqual(best.text, plaintext.decode("latin-1"))

    def test_input_and_key_parsing(self) -> None:
        self.assertEqual(xor.bytes_from_input("18001a19"), b"\x18\x00\x1a\x19")
        self.assertEqual(xor.bytes_from_input("1800", raw=True), b"1800")
        self.assertEqual(xor.key_from_input("2a", hex_key=True), b"\x2a")
        self.assertEqual(xor.key_from_input("key"), b"key")
