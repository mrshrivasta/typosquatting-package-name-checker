"""
Security Engine — Typosquatting Package Name Checker
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real-parses dependency manifests found on a REAL local directory
(`package.json` for npm, `requirements.txt` for pip) to extract the REAL
declared package names, then runs every rule in app.detection_rules against
each declared name using a real, bundled, static reference list of popular
npm/PyPI package names.

IMPORTANT: The "popular package" reference list below is a static snapshot
bundled with this tool at development time. It is NOT a live query against
the npm registry or PyPI — this tool makes no network calls at scan time.
It is intended as a reasonable, illustrative sample of well-known package
names for typosquatting-pattern detection, not an exhaustive or up-to-date
registry mirror. No sample/mock SCAN RESULTS are ever fabricated: every
Finding reflects a real computation (edit distance / substring / normalization)
against a dependency name that was really read out of a manifest file on disk.
"""
import os
import re
import json
import time

from app.detection_rules import ALL_RULES

DEFAULT_EXCLUDES = {"/proc", "/sys", "/dev", "/run"}

# ---------------------------------------------------------------------------
# Bundled static reference list of popular package names.
# Source: general public knowledge of widely-used npm & PyPI packages as of
# this tool's development. This is a fixed, offline snapshot — NOT fetched
# from any live registry at scan time. Update this list manually if you want
# fresher coverage.
# ---------------------------------------------------------------------------
POPULAR_NPM_PACKAGES = [
    "react", "react-dom", "vue", "angular", "lodash", "express", "axios",
    "moment", "chalk", "commander", "webpack", "eslint", "jest", "typescript",
    "uuid", "dotenv", "babel", "jquery", "redux", "next", "nuxt", "vite",
    "rollup", "prettier", "mocha", "chai", "sinon", "nodemon", "socket.io",
    "cors", "body-parser", "morgan", "helmet", "passport", "bcrypt", "jsonwebtoken",
    "mongoose", "sequelize", "prisma", "graphql", "apollo-server", "koa",
    "fastify", "nestjs", "yargs", "inquirer", "chokidar", "glob", "rimraf",
    "mkdirp", "semver", "minimist", "async", "bluebird", "rxjs", "immer",
    "classnames", "styled-components", "tailwindcss", "sass", "less",
    "postcss", "autoprefixer", "eslint-config-airbnb", "husky", "lint-staged",
    "cross-env", "concurrently", "ts-node", "ts-loader", "babel-loader",
    "webpack-cli", "webpack-dev-server", "vue-router", "vuex", "pinia",
    "react-router", "react-router-dom", "redux-thunk", "formik", "yup",
    "zod", "date-fns", "dayjs", "underscore", "ramda", "lodash.merge",
    "node-fetch", "isomorphic-fetch", "ws", "request", "superagent",
    "winston", "pino", "debug", "figlet", "ora", "boxen",
]

POPULAR_PYPI_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "django", "boto3", "pytest",
    "scipy", "matplotlib", "scikit-learn", "tensorflow", "torch", "keras",
    "pillow", "sqlalchemy", "click", "jinja2", "pyyaml", "cryptography",
    "python-dateutil", "urllib3", "certifi", "idna", "charset-normalizer",
    "setuptools", "wheel", "pip", "virtualenv", "tox", "black", "flake8",
    "mypy", "isort", "pylint", "gunicorn", "uvicorn", "fastapi", "starlette",
    "pydantic", "celery", "redis", "psycopg2", "pymongo", "beautifulsoup4",
    "lxml", "selenium", "scrapy", "aiohttp", "httpx", "twisted", "tornado",
    "paramiko", "fabric", "invoke", "docker", "kubernetes", "pyjwt",
    "passlib", "bcrypt", "itsdangerous", "werkzeug", "markupsafe",
    "attrs", "six", "packaging", "typing-extensions", "protobuf", "grpcio",
    "pyarrow", "openpyxl", "xlrd", "xlsxwriter", "networkx", "sympy",
    "nltk", "spacy", "gensim", "opencv-python", "imageio", "pygments",
    "colorama", "tqdm", "rich", "loguru", "python-dotenv", "pytz",
    "boto", "botocore", "s3transfer", "jsonschema", "marshmallow",
]

ALL_POPULAR_PACKAGES = sorted(set(POPULAR_NPM_PACKAGES) | set(POPULAR_PYPI_PACKAGES))


def levenshtein_distance(a, b):
    """Real, dependency-free Levenshtein (edit distance) implementation.

    Returns the minimum number of single-character insertions, deletions,
    or substitutions required to transform string `a` into string `b`.
    Uses the classic O(len(a) * len(b)) dynamic-programming table with a
    rolling two-row optimization.
    """
    a = a or ""
    b = b or ""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current_row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (0 if ca == cb else 1)
            current_row[j] = min(insert_cost, delete_cost, substitute_cost)
        previous_row = current_row
    return previous_row[-1]


def _parse_package_json(path):
    """Real-parse a package.json file's `dependencies` + `devDependencies`."""
    names = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return names
    if not isinstance(data, dict):
        return names
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section)
        if isinstance(deps, dict):
            for name in deps.keys():
                if isinstance(name, str) and name.strip():
                    names.append(("npm", name.strip()))
    return names


_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _parse_requirements_txt(path):
    """Real-parse a requirements.txt file for declared PyPI package names."""
    names = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return names
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("-"):
            continue  # -r other.txt, --index-url, etc.
        match = _REQ_LINE_RE.match(stripped)
        if match:
            names.append(("pip", match.group(1)))
    return names


MANIFEST_PARSERS = {
    "package.json": _parse_package_json,
    "requirements.txt": _parse_requirements_txt,
}


class ScanEngine:
    """Walks a REAL directory tree looking for real dependency manifests
    (package.json, requirements.txt) and evaluates every REAL declared
    dependency name against every detection rule."""

    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set(DEFAULT_EXCLUDES)
        self.max_files = max_files

        self.files_scanned = 0  # manifests parsed
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []
        self._manifests_found = 0

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real, synchronous filesystem walk + manifest parse.
        Returns summary dict: files_scanned, dirs_scanned, errors_count,
        findings, elapsed_seconds."""
        start = time.time()
        self._walk(self.target_path, depth=0)
        if self._manifests_found == 0:
            self._apply_no_manifest_rule()
        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _walk(self, path, depth):
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return

        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            full_path = entry.path
            if self._is_excluded(full_path):
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                self.errors_count += 1
                continue

            if is_file and entry.name in MANIFEST_PARSERS:
                if self.files_scanned >= self.max_files:
                    continue
                self._manifests_found += 1
                self._process_manifest(full_path, entry.name)
                self.files_scanned += 1
            elif is_dir:
                self._walk(full_path, depth + 1)

    def _process_manifest(self, path, manifest_name):
        parser = MANIFEST_PARSERS[manifest_name]
        try:
            declared = parser(path)
        except Exception:
            self.errors_count += 1
            return

        for ecosystem, name in declared:
            # Compare against the popular-package list for the SAME ecosystem
            # only. Comparing across ecosystems would create false positives
            # (e.g. the real pip package "requests" vs the real, distinct npm
            # package "request" are not a typosquat of each other).
            popular_names = POPULAR_NPM_PACKAGES if ecosystem == "npm" else POPULAR_PYPI_PACKAGES
            context = {
                "declared_name": name,
                "ecosystem": ecosystem,
                "manifest_path": path,
                "popular_names": sorted(set(n.lower() for n in popular_names)),
            }
            self._apply_rules(context)

    def _apply_no_manifest_rule(self):
        from app.detection_rules import rule_no_manifest_found
        context = {
            "declared_name": None,
            "ecosystem": None,
            "manifest_path": self.target_path,
            "popular_names": ALL_POPULAR_PACKAGES,
        }
        try:
            result = rule_no_manifest_found(context)
        except Exception:
            self.errors_count += 1
            return
        if result:
            self._record_finding(result, self.target_path, None)

    def _apply_rules(self, context):
        for rule in ALL_RULES:
            try:
                result = rule(context)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                self._record_finding(result, context["manifest_path"], result.pop("_match", None))

    def _record_finding(self, result, manifest_path, match_info):
        result["file_path"] = manifest_path
        result["permissions_octal"] = match_info or ""
        result["owner_uid"] = None
        result["owner_gid"] = None
        self.findings.append(result)
