"""
Detection Rules — Typosquatting Package Name Checker
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL `context` dict describing one declared dependency
name pulled out of a real manifest file (package.json / requirements.txt)
and returns a Finding dict if a typosquatting-risk pattern is detected.

Every rule performs a real string computation (edit distance, substring
containment, or character normalization) against the bundled static list of
popular package names in app.security_engine — nothing is hardcoded per
package name, and no rule ever "knows" in advance which dependency will be
flagged.

Supply-chain background: typosquatting is a software-supply-chain attack in
which an attacker publishes a malicious package under a name deliberately
similar to a popular, trusted package (e.g. "reqeusts" instead of
"requests"). A developer who mistypes an install command, or copy-pastes a
dependency line with a typo already baked in, can silently pull in
attacker-controlled code that runs at install time or import time.
"""

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "informational"

_SEPARATOR_CHARS = ("-", "_", ".")


def _normalize_separators(name):
    result = name
    for ch in _SEPARATOR_CHARS:
        result = result.replace(ch, "")
    return result.lower()


def _normalize_homoglyphs(name):
    """Replace common digit-for-letter homoglyph substitutions."""
    table = str.maketrans({"0": "o", "1": "l", "5": "s", "3": "e"})
    return name.lower().translate(table)


def rule_single_edit_typosquat(context):
    """TPN-001: The declared dependency name is exactly one character edit
    (insertion, deletion, or substitution — a real Levenshtein distance of 1)
    away from a well-known popular package name, and is NOT itself that
    popular name. This is the classic single-typo squat pattern
    (e.g. "reqeusts" vs "requests", "lodahs" vs "lodash") that attackers rely
    on developers mistyping during `pip install` / `npm install`, making it
    a high-confidence supply-chain risk indicator."""
    from app.security_engine import levenshtein_distance

    name = context.get("declared_name")
    popular_names = context.get("popular_names") or []
    if not name:
        return None

    lowered = name.lower()
    for popular in popular_names:
        if lowered == popular:
            continue
        distance = levenshtein_distance(lowered, popular)
        if distance == 1:
            return {
                "rule_id": "TPN-001",
                "rule_name": "Single-Edit-Distance Typosquat",
                "severity": SEVERITY_HIGH,
                "description": (
                    f"Declared dependency '{name}' is a single character edit "
                    f"away (Levenshtein distance 1) from the popular package "
                    f"'{popular}'. This is a classic typosquatting pattern — "
                    f"verify this is the package you actually intended to "
                    f"install."
                ),
                "_match": f"{name} ~ {popular}",
            }
    return None


def rule_separator_substitution_typosquat(context):
    """TPN-002: The declared dependency name matches a popular package name
    exactly once hyphens, underscores, and dots are stripped out for
    comparison (e.g. "python-dateutil" vs "python_dateutil"). Attackers
    exploit the fact that ecosystems tolerate separator variants
    inconsistently, registering a look-alike name with a swapped separator
    that is easy to overlook when reading a dependency list."""
    name = context.get("declared_name")
    popular_names = context.get("popular_names") or []
    if not name:
        return None

    lowered = name.lower()
    normalized_declared = _normalize_separators(lowered)
    for popular in popular_names:
        if lowered == popular:
            continue
        if not any(sep in popular for sep in _SEPARATOR_CHARS) and not any(sep in lowered for sep in _SEPARATOR_CHARS):
            continue  # neither side has a separator to substitute
        if normalized_declared == _normalize_separators(popular):
            return {
                "rule_id": "TPN-002",
                "rule_name": "Separator-Substitution Typosquat",
                "severity": SEVERITY_MEDIUM,
                "description": (
                    f"Declared dependency '{name}' matches the popular package "
                    f"'{popular}' once hyphens/underscores/dots are removed. "
                    f"A swapped separator is an easy-to-miss typosquat pattern "
                    f"— confirm the exact declared name is the one you intend "
                    f"to install."
                ),
                "_match": f"{name} ~ {popular}",
            }
    return None


def rule_suffix_prefix_typosquat(context):
    """TPN-003: The declared dependency name contains a popular package name
    as a substring, with extra prefix/suffix characters padding it out
    (e.g. "reactjs2", "django-official", "numpy-fast"). Attackers use this
    pattern to look like an official extension or newer version of a trusted
    package while actually being an unrelated, potentially malicious
    publication. A length-difference threshold keeps this rule from
    over-firing on legitimately distinct, longer package names."""
    name = context.get("declared_name")
    popular_names = context.get("popular_names") or []
    if not name:
        return None

    lowered = name.lower()
    for popular in popular_names:
        if lowered == popular:
            continue
        if len(popular) < 3:
            continue  # avoid noisy matches on very short popular names
        if popular in lowered:
            length_diff = len(lowered) - len(popular)
            if 0 < length_diff <= 6:
                return {
                    "rule_id": "TPN-003",
                    "rule_name": "Suffix/Prefix Padding Typosquat",
                    "severity": SEVERITY_MEDIUM,
                    "description": (
                        f"Declared dependency '{name}' contains the popular "
                        f"package name '{popular}' padded with extra "
                        f"characters ({length_diff} extra chars). This mimics "
                        f"an 'official'/'extended' variant naming pattern "
                        f"commonly used by typosquatting packages."
                    ),
                    "_match": f"{name} ~ {popular}",
                }
    return None


def rule_homoglyph_digit_typosquat(context):
    """TPN-004: The declared dependency name uses digit-for-letter
    homoglyph substitutions (0→o, 1→l/i, 5→s, 3→e) that, once normalized,
    match a popular package name exactly. Homoglyph substitution is a
    lower-effort supply-chain trick than a true typo, and is easy to miss
    visually when scanning a manifest file (e.g. "n0de-fetch" reading almost
    identically to "node-fetch")."""
    name = context.get("declared_name")
    popular_names = context.get("popular_names") or []
    if not name:
        return None

    lowered = name.lower()
    if lowered in popular_names:
        return None
    if not any(ch in lowered for ch in "0135"):
        return None  # nothing to normalize, skip

    normalized = _normalize_homoglyphs(lowered)
    for popular in popular_names:
        if normalized == popular and lowered != popular:
            return {
                "rule_id": "TPN-004",
                "rule_name": "Homoglyph Digit-Substitution Typosquat",
                "severity": SEVERITY_LOW,
                "description": (
                    f"Declared dependency '{name}' normalizes (0->o, 1->l/i, "
                    f"5->s, 3->e) to the popular package '{popular}'. Digit "
                    f"homoglyphs are a low-effort typosquat trick that reads "
                    f"almost identically to the legitimate package name."
                ),
                "_match": f"{name} ~ {popular}",
            }
    return None


def rule_ambiguous_multi_match(context):
    """TPN-005: The declared dependency name closely resembles two or more
    DIFFERENT popular package names (Levenshtein distance <= 2 from more
    than one distinct popular name). This ambiguity itself is a risk signal
    — it suggests the name was chosen (or mistyped) close enough to several
    trusted packages that a reviewer cannot be confident which one, if any,
    was actually intended."""
    from app.security_engine import levenshtein_distance

    name = context.get("declared_name")
    popular_names = context.get("popular_names") or []
    if not name:
        return None

    lowered = name.lower()
    if lowered in popular_names:
        return None

    close_matches = [p for p in popular_names if levenshtein_distance(lowered, p) <= 2]
    if len(close_matches) >= 2:
        matches_str = ", ".join(sorted(close_matches)[:5])
        return {
            "rule_id": "TPN-005",
            "rule_name": "Ambiguous Multi-Package Resemblance",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"Declared dependency '{name}' closely resembles {len(close_matches)} "
                f"different popular packages ({matches_str}). This ambiguity "
                f"makes it unclear which trusted package, if any, was intended "
                f"— review this dependency manually."
            ),
            "_match": f"{name} ~ {matches_str}",
        }
    return None


def rule_no_manifest_found(context):
    """TPN-006: No supported dependency manifest (package.json or
    requirements.txt) was found anywhere under the scanned directory. This
    is not itself a typosquatting finding, but it is reported so a reviewer
    knows this scan could not evaluate any real dependency names — an empty
    findings list from a directory with no manifest does NOT mean the
    project's dependencies are safe."""
    manifest_path = context.get("manifest_path")
    return {
        "rule_id": "TPN-006",
        "rule_name": "No Dependency Manifest Found",
        "severity": SEVERITY_INFO,
        "description": (
            f"No package.json or requirements.txt was found under "
            f"'{manifest_path}'. No dependency names could be evaluated for "
            f"typosquatting risk in this scan."
        ),
        "_match": "",
    }


ALL_RULES = [
    rule_single_edit_typosquat,
    rule_separator_substitution_typosquat,
    rule_suffix_prefix_typosquat,
    rule_homoglyph_digit_typosquat,
    rule_ambiguous_multi_match,
]

# Includes TPN-006, which is applied once per scan (not per dependency) by
# the ScanEngine directly. Listed here so `cli/main.py rules` documents all
# six rules together.
ALL_RULES_FOR_DISPLAY = ALL_RULES + [rule_no_manifest_found]
