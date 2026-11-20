from __future__ import annotations

import re

from descry.ciphers import caesar, vigenere, xor
from descry.encodings import decode as encodings
from descry.scoring import (
    Result,
    confidence,
    dedupe_results,
    english_score,
    only_letters,
)


def compact_text(text: str) -> str:
    return "".join(text.split())


def stripped_hex(text: str) -> str:
    compact = compact_text(text)
    return compact[2:] if compact.startswith(("0x", "0X")) else compact


def looks_like_hex(text: str) -> bool:
    compact = stripped_hex(text)
    return (
        len(compact) >= 4
        and len(compact) % 2 == 0
        and re.fullmatch(r"[0-9a-fA-F]+", compact) is not None
    )


def looks_like_binary(text: str) -> bool:
    compact = compact_text(text)
    return (
        len(compact) >= 8
        and len(compact) % 8 == 0
        and re.fullmatch(r"[01]+", compact) is not None
    )


def looks_like_base64(text: str) -> bool:
    compact = compact_text(text)
    return (
        bool(compact)
        and len(compact) % 4 != 1
        and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) is not None
    )


def looks_like_encoding(text: str) -> bool:
    compact = compact_text(text)
    if looks_like_binary(text) or looks_like_hex(text):
        return True
    if re.search(r"%[0-9a-fA-F]{2}", text):
        return True
    if re.fullmatch(r"[.\-\s/|]+", text) and ("." in text or "-" in text):
        return True
    if len(compact) >= 8 and re.fullmatch(r"[A-Z2-7]+={0,6}", compact.upper()):
        return True
    return looks_like_base64(text)


def encoding_results(text: str) -> list[Result]:
    results: list[Result] = []
    if looks_like_binary(text):
        decoded = encodings.decode_binary(text)
        if decoded is not None and encodings.is_readable(decoded):
            results.append(Result("binary", decoded, 95.0))
    if looks_like_hex(text):
        decoded = encodings.decode_hex(text)
        if decoded is not None:
            readable = encodings.is_readable(decoded)
            score = english_score(decoded)
            if readable and score >= 25.0:
                value = 92.0
            elif readable:
                value = 68.0
            else:
                value = 55.0
            results.append(Result("hex", decoded, value))
    if not looks_like_binary(text):
        decoded = encodings.decode_base64(text)
        if decoded is not None and encodings.is_readable(decoded):
            nested = looks_like_encoding(decoded)
            value = 92.0 if nested or english_score(decoded) >= 40 else 74.0
            results.append(Result("base64", decoded, value))
    decoded = encodings.decode_base32(text)
    if decoded is not None and encodings.is_readable(decoded):
        value = 90.0 if english_score(decoded) >= 30 else 72.0
        results.append(Result("base32", decoded, value))
    decoded = encodings.decode_url(text)
    if decoded is not None and encodings.is_readable(decoded):
        results.append(Result("url-encoding", decoded, 92.0))
    decoded = encodings.decode_morse(text)
    if decoded is not None and encodings.is_readable(decoded):
        results.append(Result("morse", decoded, 90.0))
    return results


def cipher_results(
    text: str, prefix: str = "", caesar_limit: int = 3, vigenere_limit: int = 2
) -> list[Result]:
    results: list[Result] = []
    base_score = english_score(text)
    if base_score >= 45.0:
        results.append(
            Result(f"{prefix}plaintext", text, min(99.0, base_score + 8.0))
        )
    for result in caesar.brute_force(text, limit=caesar_limit):
        shift = int(result.label.split()[1])
        if shift == 0 or result.confidence < 45.0:
            continue
        label = "caesar shift 13 (rot13)" if shift == 13 else f"caesar {result.label}"
        value = min(98.0, result.confidence + min(8.0, result.confidence - base_score))
        results.append(Result(f"{prefix}{label}", result.text, value))
    if len(only_letters(text)) >= 16:
        for result in vigenere.crack(text, limit=vigenere_limit):
            key = result.label.split("key ", 1)[-1]
            if result.confidence < 50.0 or len(set(key)) == 1:
                continue
            if result.confidence - base_score < 8.0:
                continue
            results.append(
                Result(
                    f"{prefix}vigenere key {key}",
                    result.text,
                    min(95.0, result.confidence),
                )
            )
    return results


def xor_results(text: str, prefix: str = "") -> list[Result]:
    data: bytes | None = None
    if looks_like_hex(text):
        data = xor.bytes_from_input(text)
    elif any(ord(character) < 9 or 13 < ord(character) < 32 for character in text):
        data = text.encode("utf-8")
    if data is None or len(data) < 2:
        return []
    results: list[Result] = []
    for result in xor.single_byte_crack(data, limit=3):
        if result.label == "0x00" or result.confidence < 45.0:
            continue
        results.append(
            Result(
                f"{prefix}single-byte xor {result.label}",
                result.text,
                min(97.0, result.confidence),
            )
        )
    if len(data) >= 16:
        for result in xor.repeating_key_crack(data, limit=2):
            if result.confidence < 50.0:
                continue
            results.append(
                Result(
                    f"{prefix}repeating-key xor {result.label}",
                    result.text,
                    min(95.0, result.confidence),
                )
            )
    return results


def decoded_layers(text: str, depth: int = 2) -> list[tuple[str, str]]:
    frontier: list[tuple[str, str]] = [("", text)]
    seen = {text}
    layers: list[tuple[str, str]] = []
    for _ in range(depth):
        next_frontier: list[tuple[str, str]] = []
        for prefix, current in frontier:
            for name, decoded in encodings.decode_candidates(current):
                candidate = decoded.strip()
                if not candidate or candidate in seen or not encodings.is_readable(candidate):
                    continue
                if (
                    name == "hex"
                    and english_score(candidate) < 30.0
                    and not looks_like_encoding(candidate)
                ):
                    continue
                if (
                    name == "rot13"
                    and english_score(candidate) <= english_score(current) + 2.0
                ):
                    continue
                seen.add(candidate)
                path = f"{prefix}->{name}" if prefix else name
                layers.append((path, candidate))
                next_frontier.append((path, candidate))
        frontier = next_frontier
    return layers


def detect(text: str) -> list[Result]:
    results = encoding_results(text)
    results.extend(cipher_results(text, caesar_limit=1, vigenere_limit=1))
    results.extend(xor_results(text))
    return dedupe_results(results)


def crack_all(text: str) -> list[Result]:
    collected = cipher_results(text)
    collected.extend(xor_results(text))
    for path, layer in decoded_layers(text):
        collected.extend(cipher_results(layer, f"{path} -> "))
        collected.extend(xor_results(layer, f"{path} -> "))
    final, steps = encodings.peel(text)
    if steps and final.strip() != text.strip():
        collected.append(Result(" -> ".join(steps), final, confidence(final)))
    return dedupe_results(collected)
