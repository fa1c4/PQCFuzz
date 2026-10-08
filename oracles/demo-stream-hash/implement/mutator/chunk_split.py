"""Structured chunk partition mutator."""
import random


def pair(message, split):
    return {"baseline": {"chunks": [message.hex()]},
            "mutated": {"chunks": [message[:split].hex(), message[split:].hex()]},
            "changed_fields": ["chunks"], "intervention": "change chunk partition only",
            "effective": 0 < split < len(message),
            "effectiveness_evidence": {"same_message": True, "split": split}}


def generate(seed, iteration):
    randomizer = random.Random(seed + iteration)
    message = b"BUG target payload" if iteration % 4 == 0 else randomizer.randbytes(16)
    return pair(message, 3 + randomizer.randrange(1, len(message) - 3))


def smoke_cases():
    positive = pair(b"hello world", 5)
    negative = {"baseline": {"chunks": [b"same".hex()]},
                "mutated": {"chunks": [b"same".hex()]},
                "changed_fields": [], "intervention": "none",
                "effective": False, "effectiveness_evidence": {"same_input": True}}
    return {"positive": positive, "negative": negative}
