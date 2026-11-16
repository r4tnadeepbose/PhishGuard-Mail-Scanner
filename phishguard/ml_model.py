from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Tuple


TOKEN_RE = re.compile(r"[a-z0-9@._:/-]{2,}")

# Small embedded training corpus (illustrative, lightweight). Real-world use should train on larger datasets.
PHISH_SAMPLES = [
    "urgent action required verify your account immediately click here login password reset suspended unusual sign in",
    "your mailbox will be closed confirm your identity and password now security alert verify account",
    "payment overdue invoice attached wire transfer gift card bitcoin update billing details immediately",
    "dear customer your account has been limited verify now http login security code otp",
    "congratulations you won a prize claim now urgent provide bank details confirm identity",
]
LEGIT_SAMPLES = [
    "linkedin job alert new jobs matching your search view job manage alerts unsubscribe",
    "your meeting is scheduled for tomorrow please find the agenda attached regards team",
    "monthly newsletter update product release notes documentation and support links",
    "receipt for your recent purchase thank you for your order shipping details enclosed",
    "security notification new sign in from your device if this was you no action required",
]


def _tokenize(text: str) -> List[str]:
    return TOKEN_RE.findall((text or "").lower())


@dataclass
class MLResult:
    label: str
    phishing_probability: float
    legitimate_probability: float
    confidence: float
    top_indicators: List[str]

    def to_dict(self) -> Dict:
        return {
            "label": self.label,
            "phishing_probability": round(self.phishing_probability, 4),
            "legitimate_probability": round(self.legitimate_probability, 4),
            "confidence": round(self.confidence, 4),
            "top_indicators": self.top_indicators,
            "model": "Multinomial Naive Bayes (lightweight, embedded corpus)",
        }


class NaiveBayesTextModel:
    def __init__(self):
        self.class_counts = Counter()
        self.token_counts: Dict[str, Counter] = {"phish": Counter(), "legit": Counter()}
        self.total_tokens: Dict[str, int] = {"phish": 0, "legit": 0}
        self.vocab = set()
        self.trained = False

    def train(self, phish_texts: List[str], legit_texts: List[str]):
        for t in phish_texts:
            self._add("phish", t)
        for t in legit_texts:
            self._add("legit", t)
        self.trained = True

    def _add(self, label: str, text: str):
        self.class_counts[label] += 1
        toks = _tokenize(text)
        self.token_counts[label].update(toks)
        self.total_tokens[label] += len(toks)
        self.vocab.update(toks)

    def predict(self, text: str) -> MLResult:
        if not self.trained or sum(self.class_counts.values()) == 0:
            return MLResult("unknown", 0.5, 0.5, 0.0, [])
        toks = _tokenize(text)
        if not toks:
            return MLResult("legitimate", 0.2, 0.8, 0.1, [])
        labels = ["phish", "legit"]
        total_docs = sum(self.class_counts.values())
        v = max(1, len(self.vocab))
        logp = {}
        # token contribution for explainability
        contrib = {"phish": Counter(), "legit": Counter()}
        for label in labels:
            lp = math.log((self.class_counts[label] + 1) / (total_docs + 2))
            denom = self.total_tokens[label] + v
            for tok in toks:
                c = self.token_counts[label].get(tok, 0)
                term = math.log((c + 1) / denom)
                lp += term
                contrib[label][tok] += term
            logp[label] = lp
        # softmax
        m = max(logp.values())
        ex = {k: math.exp(vv - m) for k, vv in logp.items()}
        s = sum(ex.values()) or 1.0
        p_phish = ex["phish"] / s
        p_legit = ex["legit"] / s
        label = "phishing" if p_phish >= 0.5 else "legitimate"
        confidence = abs(p_phish - p_legit)
        # top indicators favoring predicted class
        key = "phish" if label == "phishing" else "legit"
        other = "legit" if key == "phish" else "phish"
        diffs = []
        seen = set()
        for tok in toks:
            if tok in seen:
                continue
            seen.add(tok)
            # contribution difference (higher means more indicative for key class)
            d = (contrib[key].get(tok, 0) - contrib[other].get(tok, 0))
            if (key == "phish" and d > 0) or (key == "legit" and d > 0):
                diffs.append((d, tok))
        diffs.sort(reverse=True)
        top = [t for _, t in diffs[:8]]
        return MLResult(label, p_phish, p_legit, confidence, top)


_MODEL: NaiveBayesTextModel | None = None


def get_model() -> NaiveBayesTextModel:
    global _MODEL
    if _MODEL is None:
        m = NaiveBayesTextModel()
        m.train(PHISH_SAMPLES, LEGIT_SAMPLES)
        _MODEL = m
    return _MODEL


def analyze_text_ml(text: str) -> MLResult:
    return get_model().predict(text)
