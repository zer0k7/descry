from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

ALPHABET = "abcdefghijklmnopqrstuvwxyz"

ENGLISH_FREQUENCIES = {
    "a": 8.167,
    "b": 1.492,
    "c": 2.782,
    "d": 4.253,
    "e": 12.702,
    "f": 2.228,
    "g": 2.015,
    "h": 6.094,
    "i": 6.966,
    "j": 0.153,
    "k": 0.772,
    "l": 4.025,
    "m": 2.406,
    "n": 6.749,
    "o": 7.507,
    "p": 1.929,
    "q": 0.095,
    "r": 5.987,
    "s": 6.327,
    "t": 9.056,
    "u": 2.758,
    "v": 0.978,
    "w": 2.360,
    "x": 0.150,
    "y": 1.974,
    "z": 0.074,
}

COMMON_WORDS = frozenset(
    """
    a about after again against all also am an and any are as at back be because
    been before being below between both but by can could day did do does doing
    down each even every few first for from further get give go good had has have
    having he her here hers herself him himself his how i if in into is it its
    itself just know last like look made make many may me might more most much
    must my myself new no nor not now of off on once one only or other our ours
    out over own said same say see she should so some such take than that the
    their theirs them themselves then there these they thing think this those
    through time to too two under until up us use very want was way we well were
    what when where which while who whom why will with within without would you
    your yours yourself
    hello world secret message flag cipher crypto attack plaintext ciphertext
    key code password meet night computer security challenge answer hidden
    string text data value final solution crack decode encode quick brown fox
    jumps lazy dog over
    """.split()
)

COMMON_BIGRAMS = frozenset(
    """
    th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se
    ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur
    ca el ta la ns di fo ho pe ec pr no ct us ac il tr ly ge im am ow ai ay ad
    ss ee oo tt ff rr nn mm pp dd gg bb cc kk
    """.split()
)

COMMON_TRIGRAMS = frozenset(
    """
    the and ing her tha nth int ere tio ter est ers ati hat ent all eth hes
    you ion ver wit thi tch ple not but
    """.split()
)


@dataclass(frozen=True)
class Result:
    label: str
    text: str
    confidence: float


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def only_letters(text: str) -> str:
    return "".join(ch for ch in text.lower() if "a" <= ch <= "z")


def letter_counts(text: str) -> dict[str, int]:
    counts = {letter: 0 for letter in ALPHABET}
    for letter in only_letters(text):
        counts[letter] += 1
    return counts


def index_of_coincidence(text: str) -> float:
    counts = letter_counts(text).values()
    total = sum(counts)
    if total < 2:
        return 0.0
    return sum(count * (count - 1) for count in counts) / (total * (total - 1))


def chi_squared(text: str) -> float:
    letters = only_letters(text)
    total = len(letters)
    if total == 0:
        return 0.0
    counts = letter_counts(letters)
    statistic = 0.0
    for letter in ALPHABET:
        expected = total * ENGLISH_FREQUENCIES[letter] / 100.0
        statistic += (counts[letter] - expected) ** 2 / expected
    return statistic


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return printable / len(text)


def chi_component(text: str) -> float:
    letters = only_letters(text)
    if len(letters) < 2:
        return 0.0
    per_letter = chi_squared(letters) / len(letters)
    return 100.0 / (1.0 + (per_letter / 0.35) ** 1.5)


def word_component(text: str) -> float:
    words = re.findall(r"(?<![a-z0-9])[a-z]+(?![a-z0-9])", text.lower())
    if not words:
        return 0.0
    known = sum(1 for word in words if word in COMMON_WORDS)
    return 100.0 * known / len(words)


def bigram_component(text: str) -> float:
    letters = only_letters(text)
    if len(letters) < 4:
        return 0.0
    pairs = [letters[index : index + 2] for index in range(len(letters) - 1)]
    hits = sum(1 for pair in pairs if pair in COMMON_BIGRAMS)
    return clamp(180.0 * hits / len(pairs))


def trigram_component(text: str) -> float:
    letters = only_letters(text)
    if len(letters) < 6:
        return 0.0
    triples = [letters[index : index + 3] for index in range(len(letters) - 2)]
    hits = sum(1 for triple in triples if triple in COMMON_TRIGRAMS)
    return clamp(260.0 * hits / len(triples))


def english_score(text: str) -> float:
    letters = only_letters(text)
    if len(letters) < 2:
        return 0.0
    readability = printable_ratio(text)
    if readability < 0.75:
        return readability * 20.0
    density = len(letters) / len(text)
    density_factor = min(1.0, density * 1.4)
    score = (
        chi_component(text) * 0.44
        + word_component(text) * 0.30
        + bigram_component(text) * 0.16
        + trigram_component(text) * 0.10
    )
    return clamp(score * readability * density_factor)


def confidence(text: str) -> float:
    return round(100.0 * (clamp(english_score(text)) / 100.0) ** 0.5, 1)


def rank_results(
    results: Iterable[Result], limit: Optional[int] = None
) -> list[Result]:
    ordered = sorted(results, key=lambda result: result.confidence, reverse=True)
    return ordered[:limit] if limit is not None else ordered


def dedupe_results(
    results: Iterable[Result],
    limit: Optional[int] = None,
    excluded: Iterable[str] = (),
) -> list[Result]:
    excluded_labels = set(excluded)
    seen_texts: set[str] = set()
    unique: list[Result] = []
    for result in rank_results(results):
        if result.label in excluded_labels or result.text in seen_texts:
            continue
        seen_texts.add(result.text)
        unique.append(result)
        if limit is not None and len(unique) >= limit:
            break
    return unique


def frequency_rows(text: str) -> list[dict[str, object]]:
    counts = letter_counts(text)
    total = sum(counts.values())
    rows: list[dict[str, object]] = []
    for letter in ALPHABET:
        count = counts[letter]
        percent = 100.0 * count / total if total else 0.0
        rows.append(
            {
                "letter": letter,
                "count": count,
                "percent": round(percent, 2),
                "english": ENGLISH_FREQUENCIES[letter],
            }
        )
    return rows


def frequency_summary(text: str) -> dict[str, object]:
    letters = only_letters(text)
    return {
        "letters": len(letters),
        "index_of_coincidence": round(index_of_coincidence(text), 4),
        "chi_squared": round(chi_squared(text), 2) if letters else None,
        "english": confidence(text),
    }
