"""Shannon entropy calculation utilities."""
import math


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of bytes. Returns 0.0-8.0."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_file_entropy(file_obj) -> float:
    """Calculate entropy of a file object."""
    try:
        file_obj.seek(0)
        data = file_obj.read()
        file_obj.seek(0)
        return calculate_entropy(data)
    except Exception:
        return 0.0


def is_likely_encrypted(entropy: float) -> bool:
    """Return True if entropy suggests encryption (>7.2)."""
    return entropy > 7.2


def is_likely_packed(entropy: float) -> bool:
    """Return True if entropy suggests packing (>6.8)."""
    return entropy > 6.8
