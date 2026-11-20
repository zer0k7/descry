from __future__ import annotations

import math
import re
from collections import Counter
from statistics import mean
from typing import Optional

from descry.scoring import Result, confidence, english_score, rank_results


def xor_with_key(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("xor key must not be empty; pass --key or --hex-key")
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def encrypt(data: bytes, key: bytes) -> bytes:
    return xor_with_key(data, key)


def decrypt(data: bytes, key: bytes) -> bytes:
    return xor_with_key(data, key)


def hamming_distance(first: bytes, second: bytes) -> int:
    return sum(bin(left ^ right).count("1") for left, right in zip(first, second))


def normalized_distance(data: bytes, length: int) -> float:
    blocks = [
        data[index * length : (index + 1) * length]
        for index in range(min(4, len(data) // length))
    ]
    if len(blocks) < 2:
        return math.inf
    return mean(
        hamming_distance(left, right) / length
        for left, right in zip(blocks, blocks[1:])
    )


def key_length_scores(data: bytes, max_length: int = 32) -> list[tuple[int, float]]:
    limit = min(max_length, max(2, len(data) // 4))
    scores = [
        (length, normalized_distance(data, length))
        for length in range(2, limit + 1)
    ]
    return sorted(scores, key=lambda item: item[1])


def find_key_length(data: bytes, max_length: int = 32) -> int:
    rows = score_key_lengths(data, max_length)
    return rows[0][0] if rows else 1


def key_length_candidates(
    data: bytes, max_length: int = 32, limit: int = 8
) -> list[int]:
    return [length for length, _ in key_length_scores(data, max_length)[:limit]]


def score_key_lengths(
    data: bytes, max_length: int = 32, key_length: Optional[int] = None
) -> list[tuple[int, bytes, str, float]]:
    if key_length is not None and key_length > len(data):
        raise ValueError(
            "xor key length cannot exceed the input length; lower --key-length"
        )
    lengths = (
        [key_length]
        if key_length is not None
        else key_length_candidates(data, max_length)
    )
    rows: list[tuple[int, bytes, str, float]] = []
    for length in lengths:
        key = recover_repeating_key(data, length)
        plaintext = xor_with_key(data, key).decode("latin-1")
        rows.append((length, key, plaintext, confidence(plaintext)))
    return sorted(rows, key=lambda row: (row[3], -row[0]), reverse=True)


def best_byte_key(data: bytes) -> tuple[int, float]:
    best_key = 0
    best_score = -1.0
    for key in range(256):
        candidate = xor_with_key(data, bytes([key]))
        candidate_score = english_score(candidate.decode("latin-1"))
        if candidate_score > best_score:
            best_key = key
            best_score = candidate_score
    return best_key, best_score


def recover_repeating_key(data: bytes, length: int) -> bytes:
    return bytes(best_byte_key(data[index::length])[0] for index in range(length))


def single_byte_crack(data: bytes, limit: Optional[int] = None) -> list[Result]:
    results: list[Result] = []
    for key in range(256):
        plaintext = xor_with_key(data, bytes([key])).decode("latin-1")
        results.append(Result(f"0x{key:02x}", plaintext, confidence(plaintext)))
    return rank_results(results, limit)


def repeating_key_crack(
    data: bytes,
    max_length: int = 32,
    limit: Optional[int] = None,
    key_length: Optional[int] = None,
) -> list[Result]:
    if len(data) < 8:
        return []
    single_best = single_byte_crack(data, limit=1)
    confidence_floor = single_best[0].confidence + 2.0 if single_best else 0.0
    results: list[Result] = []
    seen: set[str] = set()
    for length, key, plaintext, score in score_key_lengths(
        data, max_length, key_length
    ):
        if plaintext in seen or score < confidence_floor:
            continue
        if length > 3 and max(Counter(key).values()) / len(key) >= 0.7:
            continue
        seen.add(plaintext)
        results.append(
            Result(
                f"0x{key.hex()} (len {length})",
                plaintext,
                score,
            )
        )
    return rank_results(results, limit)


def bytes_from_input(text: str, raw: bool = False) -> bytes:
    compact = "".join(text.split())
    if compact.startswith(("0x", "0X")):
        compact = compact[2:]
    if (
        not raw
        and len(compact) >= 2
        and len(compact) % 2 == 0
        and re.fullmatch(r"[0-9a-fA-F]+", compact)
    ):
        return bytes.fromhex(compact)
    return text.encode("utf-8")


def key_from_input(value: str, hex_key: bool = False) -> bytes:
    stripped = value.strip()
    if hex_key:
        compact = stripped[2:] if stripped.startswith(("0x", "0X")) else stripped
        try:
            key = bytes.fromhex(compact)
        except ValueError as error:
            raise ValueError(
                "xor key is not valid hex; pass an even-length hex string or drop --hex-key"
            ) from error
    else:
        key = stripped.encode("utf-8")
    if not key:
        raise ValueError("xor key must not be empty; pass --key or --hex-key")
    return key


def display_bytes(data: bytes) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data.hex()
    if all(character.isprintable() or character in "\n\r\t" for character in text):
        return text
    return data.hex()
