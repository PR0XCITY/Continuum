"""Words per minute and accuracy for the Train page's typing box.

Worked out in the app only, from the text in the box; nothing typed is
sent anywhere. The runtime records the timing separately through Raw
Input, never the text.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TypingStats:
    words_per_minute: int
    accuracy_percent: int
    done_percent: int

    def describe(self) -> str:
        return (
            f"{self.words_per_minute} words per minute, {self.accuracy_percent}% accurate, "
            f"{self.done_percent}% of the paragraph"
        )


def typing_stats(typed: str, target: str, elapsed_seconds: float) -> TypingStats:
    """Same rules as the browser version: 5 characters a word, position-by-position accuracy."""
    correct = sum(1 for a, b in zip(typed, target, strict=False) if a == b)
    minutes = elapsed_seconds / 60
    wpm = round(len(typed) / 5 / minutes) if minutes > 0 else 0
    accuracy = round(100 * correct / len(typed)) if typed else 100
    done = min(100, round(100 * len(typed) / len(target))) if target else 0
    return TypingStats(words_per_minute=wpm, accuracy_percent=accuracy, done_percent=done)
