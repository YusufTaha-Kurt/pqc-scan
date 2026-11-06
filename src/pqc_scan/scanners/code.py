"""Find cryptography API usage in source code.

Two engines, both driven by ``rules/code_rules.yaml`` (decision D-12):

* **Python** — the file is parsed with :mod:`ast`; imports and aliases are
  resolved, so ``from cryptography.hazmat.primitives.asymmetric import rsa as
  r; r.generate_private_key(65537, 1024)`` is recognised with its key size.
* **Java/Kotlin, JavaScript/TypeScript, Go** — comments are blanked out and
  regular-expression rules are matched; string literals give the algorithm
  name (``Cipher.getInstance("AES/ECB/PKCS5Padding")``).

Security rule (CLAUDE.md §7): observations carry the file path, line number
and API name only — never the source line itself.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Final

from pqc_scan.models import (
    Algorithm,
    Asset,
    AssetKind,
    Confidence,
    ErrorKind,
    Evidence,
    Observation,
    ScanConfig,
)
from pqc_scan.scanners.base import Scanner, ScanTargetError
from pqc_scan.scanners.code_rules import (
    ArgSpec,
    CodeRules,
    Follow,
    Language,
    PatternRule,
    PythonCallRule,
    build_algorithms,
    default_rules,
)
from pqc_scan.scanners.files import iter_files, read_candidate

LANGUAGES: Final[dict[str, Language]] = {
    ".py": Language.PYTHON,
    ".java": Language.JAVA,
    ".kt": Language.JAVA,
    ".kts": Language.JAVA,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".ts": Language.JAVASCRIPT,
    ".tsx": Language.JAVASCRIPT,
    ".mts": Language.JAVASCRIPT,
    ".cts": Language.JAVASCRIPT,
    ".go": Language.GO,
}

_FOLLOW_LINES: Final = 8  # how far key_size_after / curve_after look ahead

#: (line, api, algorithm, usage, confidence)
Hit = tuple[int, str, Algorithm, str, Confidence]


# --- Python (AST) -------------------------------------------------------------


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _canonical(name: str) -> str:
    return "Crypto." + name.removeprefix("Cryptodome.") if name.startswith("Cryptodome.") else name


class _PythonFile:
    def __init__(self, tree: ast.AST, rules: CodeRules) -> None:
        self.aliases = _import_aliases(tree)
        self.calls = {rule.call: rule for rule in rules.python_calls}
        self.attributes = {rule.name: rule for rule in rules.python_attributes}
        self.tree = tree

    def qualname(self, node: ast.expr, *, imported_only: bool = False) -> str | None:
        """Fully qualified name of ``a.b.c``; with ``imported_only`` the root
        must come from an import (so local variables are not mistaken for APIs).
        """
        if isinstance(node, ast.Name):
            if imported_only and node.id not in self.aliases:
                return None
            return _canonical(self.aliases.get(node.id, node.id))
        if isinstance(node, ast.Attribute):
            base = self.qualname(node.value, imported_only=imported_only)
            return _canonical(f"{base}.{node.attr}") if base else None
        return None

    @staticmethod
    def argument(call: ast.Call, spec: ArgSpec) -> ast.expr | None:
        for keyword in call.keywords:
            if spec.keyword and keyword.arg == spec.keyword:
                return keyword.value
        if 0 <= spec.position < len(call.args):
            arg = call.args[spec.position]
            return None if isinstance(arg, ast.Starred) else arg
        return None

    def text_value(self, node: ast.expr | None) -> str | None:
        """A string literal, or the last name of ``hashlib.sha1`` / ``ec.SECP256R1()``."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Call):
            node = node.func
        if isinstance(node, ast.Name | ast.Attribute):
            name = self.qualname(node, imported_only=True)
            return name.rsplit(".", 1)[-1] if name else None
        return None

    @staticmethod
    def int_value(node: ast.expr | None) -> int | None:
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        return None

    def hits(self) -> Iterator[Hit]:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                name = self.qualname(node.func)
                rule = self.calls.get(name) if name else None
                if rule is not None:
                    yield from self._call_hits(node, rule)
            elif isinstance(node, ast.Attribute):
                name = self.qualname(node)
                attribute = self.attributes.get(name) if name else None
                if attribute is not None and attribute.algorithm:
                    for algorithm in build_algorithms(attribute, attribute.algorithm):
                        yield (
                            node.lineno,
                            attribute.name,
                            algorithm,
                            attribute.usage,
                            Confidence.HIGH,
                        )

    def _call_hits(self, call: ast.Call, rule: PythonCallRule) -> Iterator[Hit]:
        if rule.algorithm_arg is not None:
            value = self.text_value(self.argument(call, rule.algorithm_arg))
            if value is None:
                return  # algorithm chosen at run time: nothing reliable to report
        else:
            assert rule.algorithm is not None  # noqa: S101 - guaranteed by the schema
            value = rule.algorithm
        confidence = Confidence.HIGH
        key_size = curve = None
        if rule.key_size is not None:
            key_size = self.int_value(self.argument(call, rule.key_size))
            if key_size is None:
                confidence = Confidence.MEDIUM
        if rule.curve is not None:
            curve = self.text_value(self.argument(call, rule.curve))
            if curve is None:
                confidence = Confidence.MEDIUM
        for algorithm in build_algorithms(rule, value, key_size, curve):
            yield call.lineno, rule.call, algorithm, rule.usage, confidence


def python_hits(source: str, rules: CodeRules) -> list[Hit]:
    """Crypto API calls in Python source; a file that does not parse gives []."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    return sorted(_PythonFile(tree, rules).hits(), key=lambda hit: hit[0])


# --- C-like languages (patterns) ---------------------------------------------------


def strip_comments(source: str) -> str:
    """Blank out ``//`` and ``/* */`` comments, keeping strings and line numbers."""
    out: list[str] = []
    i, n = 0, len(source)
    quote: str | None = None
    while i < n:
        char = source[i]
        if quote:
            out.append(char)
            if char == "\\" and i + 1 < n and quote != "`":
                out.append(source[i + 1])
                i += 2
                continue
            if char == quote:
                quote = None
            i += 1
            continue
        if char in "\"'`":
            quote = char
            out.append(char)
            i += 1
            continue
        if source.startswith("//", i):
            end = source.find("\n", i)
            end = n if end == -1 else end
            out.append(" " * (end - i))
            i = end
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.append(re.sub(r"[^\n]", " ", source[i:end]))
            i = end
            continue
        out.append(char)
        i += 1
    return "".join(out)


def _follow(text: str, start: int, pattern: str | None, scope: Follow) -> str | None:
    """Search ``pattern`` after a match: the next lines, or the rest of the statement."""
    if pattern is None:
        return None
    end = start
    for _ in range(_FOLLOW_LINES):
        next_newline = text.find("\n", end + 1)
        if next_newline == -1:
            end = len(text)
            break
        end = next_newline
    if scope is Follow.STATEMENT:
        semicolon = text.find(";", start, end)
        end = semicolon if semicolon != -1 else end
    match = re.search(pattern, text[start:end])
    return match.group(1) if match else None


def _pattern_hits(text: str, rule: PatternRule) -> Iterator[Hit]:
    for match in rule.compiled.finditer(text):
        groups = match.groupdict()
        value = groups.get("algorithm") or rule.algorithm
        if not value:
            continue
        value = rule.algorithm_prefix + value
        after = match.end()
        size_text = groups.get("key_size") or _follow(text, after, rule.key_size_after, rule.follow)
        curve = groups.get("curve") or _follow(text, after, rule.curve_after, rule.follow)
        key_size = int(size_text) if size_text and size_text.isdigit() else None
        line = text.count("\n", 0, match.start()) + 1
        for algorithm in build_algorithms(rule, value, key_size, curve):
            yield line, rule.api, algorithm, rule.usage, Confidence.HIGH


def pattern_hits(source: str, language: Language, rules: CodeRules) -> list[Hit]:
    text = strip_comments(source)
    hits: list[Hit] = []
    for rule in rules.patterns:
        if language in rule.languages:
            hits.extend(_pattern_hits(text, rule))
    return sorted(hits, key=lambda hit: hit[0])


def source_hits(path: Path, source: str, rules: CodeRules) -> list[Hit]:
    language = LANGUAGES.get(path.suffix.lower())
    if language is None:
        return []
    if language is Language.PYTHON:
        return python_hits(source, rules)
    return pattern_hits(source, language, rules)


# --- scanner -------------------------------------------------------------------


class CodeScanner(Scanner):
    """Report cryptography APIs used in Python, Java/Kotlin, JS/TS and Go code."""

    name = "code"

    def __init__(self, rules: CodeRules | None = None) -> None:
        self.rules = rules or default_rules()

    def scan(self, target: str, config: ScanConfig) -> list[Observation]:
        root = Path(target).expanduser()
        if not root.exists():
            raise ScanTargetError(ErrorKind.INVALID_TARGET, "path does not exist")
        base = root if root.is_dir() else root.parent
        observations: list[Observation] = []
        for path in iter_files(root, config):
            if path.suffix.lower() not in LANGUAGES:
                continue
            data = read_candidate(path, config.max_file_size)
            if data is None:
                continue
            hits = source_hits(path, data.decode("utf-8", errors="replace"), self.rules)
            if not hits:
                continue
            asset = Asset(
                id=path.absolute().as_uri(),
                kind=AssetKind.SOURCE_FILE,
                location=path.relative_to(base).as_posix(),
            )
            observations += [
                Observation(
                    asset=asset,
                    algorithm=algorithm,
                    usage=f"code.{usage}",
                    scanner=self.name,
                    evidence=Evidence(line=line, detail=api),
                    confidence=confidence,
                )
                for line, api, algorithm, usage, confidence in hits
            ]
        return observations
