from __future__ import annotations

import base64
import binascii
import re
from collections import deque
from urllib.parse import unquote

from descry.ciphers import caesar
from descry.scoring import english_score

MORSE_CODE = {
    "a": ".-",
    "b": "-...",
    "c": "-.-.",
    "d": "-..",
    "e": ".",
    "f": "..-.",
    "g": "--.",
    "h": "....",
    "i": "..",
    "j": ".---",
    "k": "-.-",
    "l": ".-..",
    "m": "--",
    "n": "-.",
    "o": "---",
    "p": ".--.",
    "q": "--.-",
    "r": ".-.",
    "s": "...",
    "t": "-",
    "u": "..-",
    "v": "...-",
    "w": ".--",
    "x": "-..-",
    "y": "-.--",
    "z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    ".": ".-.-.-",
    ",": "--..--",
    "?": "..--..",
    "'": ".----.",
    "!": "-.-.--",
    "/": "-..-.",
    "(": "-.--.",
    ")": "-.--.-",
    "&": ".-...",
    ":": "---...",
    ";": "-.-.-.",
    "=": "-...-",
    "+": ".-.-.",
    "-": "-....-",
    "_": "..--.-",
    '"': ".-..-.",
    "$": "...-..-",
    "@": ".--.-.",
}

MORSE_DECODE = {code: character for character, code in MORSE_CODE.items()}


def decode_bytes(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def is_readable(text: str) -> bool:
    if not text:
        return False
    printable = sum(
        1 for character in text if character in "\n\r\t" or 32 <= ord(character) <= 126
    )
    if printable / len(text) < 0.95:
        return False
    return any(character.isalpha() for character in text)


def decode_base64(text: str) -> str | None:
    compact = "".join(text.split())
    if not compact or len(compact) % 4 == 1:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        return None
    padded = compact + "=" * ((4 - len(compact) % 4) % 4)
    try:
        data = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decode_bytes(data)


def decode_base32(text: str) -> str | None:
    compact = "".join(text.split()).upper()
    if not compact or not re.fullmatch(r"[A-Z2-7]+={0,6}", compact):
        return None
    padded = compact + "=" * ((8 - len(compact) % 8) % 8)
    try:
        data = base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError):
        return None
    return decode_bytes(data)


def decode_hex(text: str) -> str | None:
    compact = "".join(text.split())
    if compact.startswith(("0x", "0X")):
        compact = compact[2:]
    if len(compact) < 2 or len(compact) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", compact):
        return None
    try:
        return decode_bytes(bytes.fromhex(compact))
    except ValueError:
        return None


def decode_binary(text: str) -> str | None:
    compact = "".join(text.split())
    if len(compact) < 8 or len(compact) % 8 != 0:
        return None
    if not re.fullmatch(r"[01]+", compact):
        return None
    data = bytes(int(compact[index : index + 8], 2) for index in range(0, len(compact), 8))
    return decode_bytes(data)


def decode_url(text: str) -> str | None:
    if not re.search(r"%[0-9a-fA-F]{2}", text):
        return None
    decoded = unquote(text)
    return decoded if decoded != text else None


def decode_morse(text: str) -> str | None:
    stripped = text.strip()
    if not stripped or not re.fullmatch(r"[.\-\s/|]+", stripped):
        return None
    if "." not in stripped and "-" not in stripped:
        return None
    normalized = stripped.replace("|", "/")
    if "/" in normalized:
        words = [word.strip() for word in normalized.split("/") if word.strip()]
    else:
        words = [
            chunk.strip()
            for chunk in re.split(r"\s{3,}", normalized)
            if chunk.strip()
        ]
    decoded_words: list[str] = []
    for word in words:
        letters: list[str] = []
        for token in word.split():
            if token not in MORSE_DECODE:
                return None
            letters.append(MORSE_DECODE[token])
        decoded_words.append("".join(letters))
    return " ".join(decoded_words) if decoded_words else None


def rot13(text: str) -> str:
    return caesar.shift_text(text, 13)


def decode_candidates(text: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    for name, decoder in (
        ("base64", decode_base64),
        ("base32", decode_base32),
        ("hex", decode_hex),
        ("binary", decode_binary),
        ("url", decode_url),
        ("morse", decode_morse),
    ):
        decoded = decoder(text)
        if decoded is not None and decoded != text and decoded.strip():
            candidates.append((name, decoded))
    rotated = rot13(text)
    if rotated != text and any(character.isalpha() for character in text):
        candidates.append(("rot13", rotated))
    return candidates


def peel(text: str, max_depth: int = 6) -> tuple[str, list[str]]:
    start = text.strip()
    best_text = start
    best_steps: list[str] = []
    best_score = english_score(start)
    queue: deque[tuple[str, list[str], int]] = deque([(start, [], 0)])
    seen = {start}
    visited = 0
    while queue and visited < 200:
        current, steps, depth = queue.popleft()
        visited += 1
        if depth >= max_depth:
            continue
        for name, decoded in decode_candidates(current):
            candidate = decoded.strip()
            if not candidate or candidate in seen or not is_readable(candidate):
                continue
            seen.add(candidate)
            path = steps + [name]
            score = english_score(candidate)
            if score > best_score + 0.5:
                best_text = candidate
                best_steps = path
                best_score = score
            queue.append((candidate, path, depth + 1))
    return best_text, best_steps
