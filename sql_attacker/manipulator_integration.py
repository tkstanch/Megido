"""
Integration bridge between the SQL Attacker app and the Manipulator app.

Provides helpers for fetching SQLi-related manipulation tricks, payloads,
and encoding techniques from the Manipulator app's models and utility
functions, and for applying them to SQL injection payloads.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def get_sqli_manipulation_tricks() -> List[Dict]:
    """
    Fetch all SQLi-related manipulation tricks from the Manipulator app.

    Returns a list of dicts with keys: id, name, technique, description,
    example, effectiveness, target_defense.  Returns an empty list if the
    Manipulator models are not available or no SQLi type exists.
    """
    try:
        from manipulator.models import VulnerabilityType, PayloadManipulation
        sqli_type = VulnerabilityType.objects.filter(name='SQLi').first()
        if not sqli_type:
            return []
        tricks = PayloadManipulation.objects.filter(vulnerability=sqli_type)
        return [
            {
                'id': t.id,
                'name': t.name,
                'technique': t.technique,
                'description': t.description,
                'example': t.example,
                'effectiveness': t.effectiveness,
                'target_defense': t.target_defense,
            }
            for t in tricks
        ]
    except Exception as exc:
        logger.warning("Could not fetch SQLi manipulation tricks: %s", exc)
        return []


def get_sqli_payloads() -> List[Dict]:
    """
    Fetch pre-loaded SQLi payloads from the Manipulator app.

    Returns a list of dicts with keys: id, name, payload_text, description,
    bypass_technique, is_obfuscated.  Returns an empty list on failure.
    """
    try:
        from manipulator.models import VulnerabilityType, Payload
        sqli_type = VulnerabilityType.objects.filter(name='SQLi').first()
        if not sqli_type:
            return []
        payloads = Payload.objects.filter(vulnerability=sqli_type)
        return [
            {
                'id': p.id,
                'name': p.name,
                'payload_text': p.payload_text,
                'description': p.description,
                'bypass_technique': p.bypass_technique,
                'is_obfuscated': p.is_obfuscated,
            }
            for p in payloads
        ]
    except Exception as exc:
        logger.warning("Could not fetch SQLi payloads: %s", exc)
        return []


def get_available_encodings_for_sqli() -> Dict[str, str]:
    """
    Return all encoding techniques available via the Manipulator app.

    Delegates to ``manipulator.encoding_utils.get_available_encodings``.
    Falls back to an empty dict if the module is unavailable.
    """
    try:
        from manipulator.encoding_utils import get_available_encodings
        return get_available_encodings()
    except Exception as exc:
        logger.warning("Could not fetch available encodings: %s", exc)
        return {}


def apply_manipulations_to_payload(
    payload: str,
    encoding_names: Optional[List[str]] = None,
    trick_ids: Optional[List[int]] = None,
) -> List[str]:
    """
    Apply selected encoding techniques and/or manipulation tricks to a payload.

    Args:
        payload: Raw SQL injection payload string.
        encoding_names: List of encoding technique keys (e.g. ['url', 'sql_comment']).
        trick_ids: List of PayloadManipulation IDs whose ``technique`` field
                   will be appended to the payload to generate variants.

    Returns:
        A list of manipulated payload variants (may include the original if
        transformations fail).  The list will not be empty.
    """
    variants: List[str] = []

    # Apply each encoding as an independent variant
    if encoding_names:
        try:
            from manipulator.encoding_utils import apply_encoding
            for enc_name in encoding_names:
                encoded, success, _err = apply_encoding(payload, enc_name)
                if success and encoded and encoded != payload:
                    variants.append(encoded)
        except Exception as exc:
            logger.warning("Could not apply encodings to payload: %s", exc)

    # Apply each manipulation trick as an independent variant
    if trick_ids:
        try:
            from manipulator.models import PayloadManipulation
            tricks = PayloadManipulation.objects.filter(id__in=trick_ids)
            for trick in tricks:
                if trick.technique:
                    # Replace the placeholder {payload} in the technique pattern,
                    # or simply append the technique to the payload.
                    if '{payload}' in trick.technique:
                        variant = trick.technique.replace('{payload}', payload)
                    else:
                        variant = trick.technique + payload
                    variants.append(variant)
        except Exception as exc:
            logger.warning("Could not apply manipulation tricks to payload: %s", exc)

    # Always include the original payload so the engine still has a baseline
    if not variants:
        variants.append(payload)

    return variants


def get_manipulator_context() -> Dict:
    """
    Return a context dict containing all Manipulator data needed by templates.

    Keys:
        manipulator_tricks      – list of SQLi manipulation trick dicts
        manipulator_encodings   – dict of encoding_key -> description
        manipulator_payloads    – list of SQLi payload dicts
    """
    return {
        'manipulator_tricks': get_sqli_manipulation_tricks(),
        'manipulator_encodings': get_available_encodings_for_sqli(),
        'manipulator_payloads': get_sqli_payloads(),
    }
