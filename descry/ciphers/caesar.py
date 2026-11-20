from __future__ import annotations

from typing import Optional

from descry.scoring import Result, confidence, rank_results


def shift_letter(letter: str, shift: int) -> str:
    if "a" <= letter <= "z":
        base = ord("a")
    elif "A" <= letter <= "Z":
        base = ord("A")
    else:
        return letter
    return chr((ord(letter) - base + shift) % 26 + base)


def shift_text(text: str, shift: int) -> str:
    return "".join(shift_letter(letter, shift) for letter in text)


def encrypt(text: str, shift: int) -> str:
    return shift_text(text, shift)


def decrypt(text: str, shift: int) -> str:
    return shift_text(text, -shift)


def brute_force(text: str, limit: Optional[int] = None) -> list[Result]:
    results: list[Result] = []
    for shift in range(26):
        plaintext = decrypt(text, shift)
        results.append(Result(f"shift {shift}", plaintext, confidence(plaintext)))
    return rank_results(results, limit)
