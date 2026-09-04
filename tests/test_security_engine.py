"""Tests for the Security Engine and Detection Rules — rule-level tests run
against synthetic context dicts, and engine-level tests run against REAL
temp directories containing REAL package.json / requirements.txt manifest
files on disk (no mocking of the filesystem or of any rule)."""
import os
import json
import tempfile
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine, levenshtein_distance, ALL_POPULAR_PACKAGES
from app.detection_rules import (
    rule_single_edit_typosquat,
    rule_separator_substitution_typosquat,
    rule_suffix_prefix_typosquat,
    rule_homoglyph_digit_typosquat,
    rule_ambiguous_multi_match,
    rule_no_manifest_found,
)


# ---------------------------------------------------------------------------
# Levenshtein distance — direct unit tests against known distance pairs
# ---------------------------------------------------------------------------

def test_levenshtein_identical_strings():
    assert levenshtein_distance("requests", "requests") == 0


def test_levenshtein_single_substitution():
    assert levenshtein_distance("requezts", "requests") == 1
    assert levenshtein_distance("lodach", "lodash") == 1


def test_levenshtein_single_insertion():
    assert levenshtein_distance("flask", "flasks") == 1


def test_levenshtein_single_deletion():
    assert levenshtein_distance("expres", "express") == 1


def test_levenshtein_known_classic_pair():
    # classic textbook example
    assert levenshtein_distance("kitten", "sitting") == 3


def test_levenshtein_empty_strings():
    assert levenshtein_distance("", "") == 0
    assert levenshtein_distance("", "abc") == 3
    assert levenshtein_distance("abc", "") == 3


# ---------------------------------------------------------------------------
# Rule-level tests — synthetic context dicts
# ---------------------------------------------------------------------------

def test_rule_single_edit_typosquat_detects_real_typo():
    # "flasks" is a real Levenshtein distance of 1 (one insertion) from "flask"
    context = {"declared_name": "flasks", "ecosystem": "pip", "manifest_path": "x", "popular_names": ALL_POPULAR_PACKAGES}
    result = rule_single_edit_typosquat(context)
    assert result is not None
    assert result["rule_id"] == "TPN-001"
    assert "flask" in result["_match"]


def test_rule_single_edit_typosquat_ignores_exact_match():
    from app.security_engine import POPULAR_PYPI_PACKAGES
    context = {"declared_name": "django", "ecosystem": "pip", "manifest_path": "x", "popular_names": POPULAR_PYPI_PACKAGES}
    assert rule_single_edit_typosquat(context) is None


def test_rule_single_edit_typosquat_ignores_unrelated_name():
    context = {"declared_name": "my-totally-unique-internal-lib", "ecosystem": "pip", "manifest_path": "x", "popular_names": ALL_POPULAR_PACKAGES}
    assert rule_single_edit_typosquat(context) is None


def test_rule_separator_substitution_typosquat():
    context = {"declared_name": "python_dateutil", "ecosystem": "pip", "manifest_path": "x", "popular_names": ALL_POPULAR_PACKAGES}
    result = rule_separator_substitution_typosquat(context)
    assert result is not None
    assert result["rule_id"] == "TPN-002"


def test_rule_separator_substitution_ignores_exact_match():
    context = {"declared_name": "python-dateutil", "ecosystem": "pip", "manifest_path": "x", "popular_names": ALL_POPULAR_PACKAGES}
    assert rule_separator_substitution_typosquat(context) is None


def test_rule_suffix_prefix_typosquat():
    context = {"declared_name": "requestsplus", "ecosystem": "pip", "manifest_path": "x", "popular_names": ALL_POPULAR_PACKAGES}
    result = rule_suffix_prefix_typosquat(context)
    assert result is not None
    assert result["rule_id"] == "TPN-003"


def test_rule_suffix_prefix_typosquat_ignores_exact_match():
    context = {"declared_name": "django", "ecosystem": "pip", "manifest_path": "x", "popular_names": ALL_POPULAR_PACKAGES}
    assert rule_suffix_prefix_typosquat(context) is None


def test_rule_homoglyph_digit_typosquat():
    context = {"declared_name": "n0de-fetch", "ecosystem": "npm", "manifest_path": "x", "popular_names": ALL_POPULAR_PACKAGES}
    result = rule_homoglyph_digit_typosquat(context)
    assert result is not None
    assert result["rule_id"] == "TPN-004"


def test_rule_homoglyph_digit_typosquat_ignores_names_without_digits():
    context = {"declared_name": "requests", "ecosystem": "pip", "manifest_path": "x", "popular_names": ALL_POPULAR_PACKAGES}
    assert rule_homoglyph_digit_typosquat(context) is None


def test_rule_ambiguous_multi_match():
    # "reqests" is within distance 2 of both "requests" and possibly others
    context = {"declared_name": "reqests", "ecosystem": "pip", "manifest_path": "x", "popular_names": ["requests", "request", "requesto", "unrelated"]}
    result = rule_ambiguous_multi_match(context)
    assert result is not None
    assert result["rule_id"] == "TPN-005"


def test_rule_no_manifest_found():
    context = {"declared_name": None, "ecosystem": None, "manifest_path": "/some/dir", "popular_names": ALL_POPULAR_PACKAGES}
    result = rule_no_manifest_found(context)
    assert result is not None
    assert result["rule_id"] == "TPN-006"


# ---------------------------------------------------------------------------
# Engine-level tests — REAL temp directories with REAL manifest files
# ---------------------------------------------------------------------------

def test_engine_detects_typosquat_in_real_package_json():
    tmpdir = tempfile.mkdtemp()
    try:
        manifest = {
            "name": "sample-project",
            "dependencies": {
                "chalks": "^1.0.0",  # deliberate single-char typosquat of "chalk" (npm)
                "express": "^4.18.0",  # legitimate, popular package
            },
            "devDependencies": {
                "lodahs": "^4.17.0",  # separator/transposition-style near-miss of "lodash"
            },
        }
        with open(os.path.join(tmpdir, "package.json"), "w") as fh:
            json.dump(manifest, fh)

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0

        flagged_names = set()
        for f in result["findings"]:
            flagged_names.add(f["permissions_octal"].split(" ~ ")[0])

        assert "chalks" in flagged_names
        assert "express" not in flagged_names
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_typosquat_in_real_requirements_txt():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "requirements.txt"), "w") as fh:
            fh.write("requezts==2.31.0\n")  # deliberate single-char typosquat of "requests"
            fh.write("flask==2.3.0\n")
            fh.write("# a comment line\n")
            fh.write("\n")

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()

        assert result["files_scanned"] == 1
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "TPN-001" in rule_ids

        flagged_names = {f["permissions_octal"].split(" ~ ")[0] for f in result["findings"]}
        assert "requezts" in flagged_names
        assert "flask" not in flagged_names
    finally:
        shutil.rmtree(tmpdir)


def test_engine_no_manifest_found_produces_tpn006():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "readme.txt"), "w") as fh:
            fh.write("nothing to see here")

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "TPN-006" in rule_ids
        assert result["files_scanned"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_engine_clean_manifest_produces_no_typosquat_findings():
    tmpdir = tempfile.mkdtemp()
    try:
        manifest = {"dependencies": {"react": "^18.0.0", "express": "^4.18.0"}}
        with open(os.path.join(tmpdir, "package.json"), "w") as fh:
            json.dump(manifest, fh)

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()
        assert result["findings"] == []
    finally:
        shutil.rmtree(tmpdir)


def test_excluded_paths_are_skipped():
    tmpdir = tempfile.mkdtemp()
    try:
        excluded = os.path.join(tmpdir, "excluded")
        os.mkdir(excluded)
        manifest = {"dependencies": {"reqeusts": "1.0.0"}}
        with open(os.path.join(excluded, "package.json"), "w") as fh:
            json.dump(manifest, fh)

        engine = ScanEngine(tmpdir, max_depth=3, excludes=[excluded])
        result = engine.run()
        assert all(excluded not in f["file_path"] for f in result["findings"])
    finally:
        shutil.rmtree(tmpdir)
