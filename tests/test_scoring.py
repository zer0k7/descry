import random
import string
import unittest

from descry.scoring import (
    Result,
    confidence,
    english_score,
    index_of_coincidence,
    rank_results,
)

PLAIN = (
    "The quick brown fox jumps over the lazy dog. This is a normal English "
    "sentence with enough words to score well. "
)


class ScoringTests(unittest.TestCase):
    def test_english_scores_above_random_text(self) -> None:
        random.seed(7)
        samples = [
            "".join(random.choice(string.ascii_letters + " ") for _ in range(160))
            for _ in range(5)
        ]
        for sample in samples:
            with self.subTest(sample=sample[:20]):
                self.assertGreater(english_score(PLAIN * 4), english_score(sample))

    def test_confidence_is_normalized(self) -> None:
        for text in ["", "hello", PLAIN, "qzxv qzxv qzxv", "12345"]:
            with self.subTest(text=text[:12]):
                value = confidence(text)
                self.assertGreaterEqual(value, 0.0)
                self.assertLessEqual(value, 100.0)

    def test_index_of_coincidence_separates_english_from_random(self) -> None:
        random.seed(11)
        random_text = "".join(random.choice(string.ascii_lowercase) for _ in range(400))
        self.assertGreater(index_of_coincidence(PLAIN * 5), 0.055)
        self.assertLess(index_of_coincidence(random_text), 0.05)

    def test_rank_results_sorts_and_limits(self) -> None:
        results = [
            Result("low", "aaaa", 10.0),
            Result("high", "the quick brown fox", 90.0),
            Result("mid", "hello world", 50.0),
        ]
        ranked = rank_results(results, 2)
        self.assertEqual([result.label for result in ranked], ["high", "mid"])
