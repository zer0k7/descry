from __future__ import annotations

from collections import Counter
from statistics import mean
from typing import Optional

from descry.ciphers import caesar
from descry.scoring import (
    ALPHABET,
    Result,
    confidence,
    english_score,
    index_of_coincidence,
    only_letters,
    rank_results,
)


def validated_key(key: str) -> str:
    stripped = key.strip()
    if not stripped or not stripped.isascii() or not stripped.isalpha():
        raise ValueError("vigenere key must contain letters only; try --key LEMON")
    return stripped.lower()


def transform(text: str, key: str, direction: int) -> str:
    key_letters = validated_key(key)
    output: list[str] = []
    position = 0
    for character in text:
        if character.isalpha() and character.isascii():
            shift = ord(key_letters[position % len(key_letters)]) - ord("a")
            output.append(caesar.shift_letter(character, direction * shift))
            position += 1
        else:
            output.append(character)
    return "".join(output)


def encrypt(text: str, key: str) -> str:
    return transform(text, key, 1)


def decrypt(text: str, key: str) -> str:
    return transform(text, key, -1)


def columns(text: str, length: int) -> list[str]:
    letters = only_letters(text)
    return [letters[index::length] for index in range(length)]


def average_ic(text: str, length: int) -> float:
    chunks = [chunk for chunk in columns(text, length) if len(chunk) >= 2]
    if not chunks:
        return 0.0
    return mean(index_of_coincidence(chunk) for chunk in chunks)


def repeated_distances(text: str, ngram: int = 3) -> list[int]:
    letters = only_letters(text)
    positions: dict[str, list[int]] = {}
    distances: list[int] = []
    for index in range(len(letters) - ngram + 1):
        gram = letters[index : index + ngram]
        for earlier in positions.get(gram, [])[-6:]:
            distances.append(index - earlier)
        positions.setdefault(gram, []).append(index)
    return distances


def kasiski_key_lengths(text: str, max_length: int) -> list[int]:
    counts: Counter[int] = Counter()
    for distance in repeated_distances(text):
        for length in range(2, max_length + 1):
            if distance % length == 0:
                counts[length] += 1
    return [length for length, _ in counts.most_common()]


def key_length_scores(text: str, max_length: int = 20) -> list[tuple[int, float]]:
    letters = len(only_letters(text))
    if letters < 8:
        return []
    limit = min(max_length, max(2, letters // 4))
    kasiski = set(kasiski_key_lengths(text, limit)[:8])
    scores: list[tuple[int, float]] = []
    for length in range(2, limit + 1):
        coincidence = average_ic(text, length)
        bonus = 0.003 if length in kasiski else 0.0
        scores.append((length, coincidence + bonus - 0.00008 * length))
    return sorted(scores, key=lambda item: item[1], reverse=True)


def candidate_key_lengths(text: str, max_length: int = 20) -> list[int]:
    if len(only_letters(text)) < 6:
        return [1]
    scores = key_length_scores(text, max_length)
    if not scores:
        return [1]
    kasiski = kasiski_key_lengths(
        text, min(max_length, max(2, len(only_letters(text)) // 4))
    )
    ordered: list[int] = []
    for length in kasiski[:5] + [length for length, _ in scores]:
        if length not in ordered:
            ordered.append(length)
    return ordered[:8] or [1]


def best_shift_for_column(column: str) -> int:
    best_shift = 0
    best_score = -1.0
    for shift in range(26):
        candidate = caesar.decrypt(column, shift)
        candidate_score = english_score(candidate)
        if candidate_score > best_score:
            best_shift = shift
            best_score = candidate_score
    return best_shift


def recover_key_for_length(text: str, length: int) -> str:
    letters = only_letters(text)
    shifts = [
        best_shift_for_column(letters[index::length]) for index in range(length)
    ]
    return "".join(ALPHABET[shift] for shift in shifts).upper()


def crack(
    text: str, max_length: int = 20, limit: Optional[int] = None
) -> list[Result]:
    if len(only_letters(text)) < 2:
        return []
    results: list[Result] = []
    seen: set[str] = set()
    for length in candidate_key_lengths(text, max_length):
        key = recover_key_for_length(text, length)
        plaintext = decrypt(text, key)
        if plaintext in seen:
            continue
        seen.add(plaintext)
        results.append(Result(f"key {key}", plaintext, confidence(plaintext)))
    return rank_results(results, limit)
