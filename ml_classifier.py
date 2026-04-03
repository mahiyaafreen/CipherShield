# ml_classifier.py
import re

# -------------------------------------------------------
# VERY SIMPLE ML-LIKE TEXT CLASSIFIER (pure-python)
# -------------------------------------------------------
# Labels:
#   SAFE
#   WARNING
#   SUSPICIOUS
# -------------------------------------------------------

SUSPICIOUS_WORDS = [
    "password", "bank", "account", "otp", "secret",
    "pin", "loan", "money", "transfer", "urgent"
]

WARNING_WORDS = [
    "click", "verify", "update", "confirm",
    "alert", "security", "limited", "action"
]


def predict_suspicion(text):
    text_lower = text.lower()

    score = 0

    # suspicious words → +2 each
    for w in SUSPICIOUS_WORDS:
        if w in text_lower:
            score += 2

    # warning words → +1 each
    for w in WARNING_WORDS:
        if w in text_lower:
            score += 1

    # label based on score
    if score >= 4:
        label = "SUSPICIOUS"
    elif score >= 2:
        label = "WARNING"
    else:
        label = "SAFE"

    return label, score
