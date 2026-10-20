#!/usr/bin/env python3
"""
t1027010_hunter.py — static-analysis hunter for MITRE ATT&CK T1027.010
(Command Obfuscation) indicators in PowerShell source or exported PowerShell
Script Block Logging (Event ID 4104) text.

WHAT THIS IS
    A regex/text based static analyzer. It reads PowerShell source (.ps1,
    .psm1, .psd1) or plain-text exports of Event ID 4104 script block log
    content and flags textual patterns associated with T1027.010:
      1. Wildcard alias/command resolution feeding execution
         (Get-Alias/Get-Command with wildcards resolving to IEX/IRM/IWR/etc.,
         including a bounded variable-indirect form: pattern assigned to a
         variable a few lines earlier, then passed to Get-Alias/Get-Command)
      2. Character masking (backtick-splitting, case randomization, string
         concatenation/reordering, Unicode homoglyph substitution, char-code
         array reconstruction, -f format-operator reconstruction)
      3. Environment-variable-based command string reconstruction
      4. Encoded-command / download-cradle patterns (-EncodedCommand,
         base64 -> IEX, WebClient/IWR/IRM download-and-execute chains)

    Detection matching runs against a comment-blanked copy of the source
    ('#...' line comments and '<# ... #>' block comments are ignored) so
    plain-English comments that merely mention a flag/cmdlet name don't
    trigger findings. This is NOT a full PowerShell parser — see
    README.md "What this tool will never catch" and HANDOFF.md for the
    specific, verified gaps in both directions (false positive and false
    negative) that remain after this comment-stripping fix.

WHAT THIS IS NOT
    This tool NEVER evaluates, executes, decodes-and-runs, or shells out to
    PowerShell (or anything else) against the content it analyzes. It does
    not call eval(), exec(), os.system(), or subprocess against input data.
    It only reads text and applies regular expressions. This is a hard
    safety requirement for this tool, not a style choice — see README.md.

USAGE
    python3 t1027010_hunter.py <file_or_directory> [--json] [--min-confidence LEVEL]

    LEVEL is one of: low, medium, high (default: low = show everything)

ATT&CK MAPPING
    Every finding is tagged with the sub-technique T1027.010 (Command
    Obfuscation) and its parent T1027 (Obfuscated Files or Information).
    See README.md for the full rationale per category.

Pure Python 3 standard library only. No third-party dependencies, no pip
install required — this is meant to be run by an attendee on a laptop with
nothing but python3 installed.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Tuple

# --------------------------------------------------------------------------
# ATT&CK metadata (kept centralized so every finding is tagged consistently)
# --------------------------------------------------------------------------

TECHNIQUE_ID = "T1027.010"
TECHNIQUE_NAME = "Command Obfuscation"
TECHNIQUE_URL = "https://attack.mitre.org/techniques/T1027/010/"
PARENT_ID = "T1027"
PARENT_NAME = "Obfuscated Files or Information"
PARENT_URL = "https://attack.mitre.org/techniques/T1027/"

CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}

EXTENSIONS = {".ps1", ".psm1", ".psd1", ".txt", ".log"}

# --------------------------------------------------------------------------
# Finding data model
# --------------------------------------------------------------------------


@dataclass
class Finding:
    file: str
    line: int
    category: str          # short machine-readable category key
    label: str              # human-readable category label
    snippet: str
    confidence: str         # "LOW" | "MEDIUM" | "HIGH"
    rationale: str
    technique_id: str = TECHNIQUE_ID
    technique_name: str = TECHNIQUE_NAME
    technique_url: str = TECHNIQUE_URL
    parent_id: str = PARENT_ID
    parent_name: str = PARENT_NAME
    parent_url: str = PARENT_URL

    def to_dict(self) -> dict:
        return asdict(self)


def _truncate(s: str, n: int = 200) -> str:
    s = s.strip()
    if len(s) <= n:
        return s
    return s[: n - 3] + "..."


# --------------------------------------------------------------------------
# Comment stripping (matching-only — never shown to the user)
# --------------------------------------------------------------------------
#
# Round-1 critique finding [HIGH]: a realistic, well-commented deploy script
# lit up HIGH findings on plain-English comment lines that merely *mentioned*
# a flag name (e.g. "# Legitimate use of -EncodedCommand to avoid quoting
# hell..."), flipping the advertised CI-gate exit code on clean code. Every
# detector now runs against a comment-blanked copy of the text, not the raw
# text. Original lines (with comments intact) are still what gets shown in
# the `snippet` field, so output stays human-readable — only the *matching*
# is comment-blind-corrected. This is a lightweight approximation of
# PowerShell's comment/string syntax, not a full tokenizer/parser: it
# handles the common cases (# to end of line, <# ... #> blocks, '#' inside
# quoted strings, and — round-2 addition below — here-string bodies) but is
# not guaranteed correct for every pathological edge case a real PowerShell
# parser would handle (see HANDOFF.md).
#
# Round-2 critique finding: a plausible "T1027.010 cheat sheet" helper
# script — exactly the kind of file this talk's audience would write for
# themselves — printed reference prose via a here-string (`@"..."@`)
# mentioning -EncodedCommand/iex/$env: by name, and every line of that
# prose was scanned as if it were live code, firing 2 HIGH + 1 MEDIUM and
# flipping the exit code. This had already been named as the single
# highest-priority untested risk in this file's own HANDOFF.md before it
# was found. Fixed the same way block comments are handled: here-string
# bodies are blanked before matching, not shown-but-ignored — just ignored.

_BLOCK_COMMENT_RE = re.compile(r"<#.*?#>", re.DOTALL)
_HERESTRING_DQ_RE = re.compile(r'@"[ \t]*\r?\n(?:.*\r?\n)*?[ \t]*"@')
_HERESTRING_SQ_RE = re.compile(r"@'[ \t]*\r?\n(?:.*\r?\n)*?[ \t]*'@")


def _blank_span_preserving_newlines(m: "re.Match[str]") -> str:
    """Shared replacement helper: blank every character in a matched span
    except '\\n'/'\\r', so line numbers stay aligned for both block
    comments and here-strings."""
    return "".join(ch if ch in ("\n", "\r") else " " for ch in m.group(0))


def _blank_herestrings(text: str) -> str:
    """Replace @"..."@ / @'...'@ here-string bodies with whitespace of the
    same shape (newlines/carriage-returns preserved). Here-strings are
    routinely used for prose — help text, log message templates,
    cheat-sheet/handout content, usage banners — that can easily *contain*
    the literal names of dangerous cmdlets/flags while describing them,
    not invoking them. Same rationale, and same bounded/approximate
    caveats, as _blank_block_comments() below. Must run before block
    comments and line comments so a literal '#'/'<#'/'#>' inside
    here-string prose (e.g. a cheat sheet that mentions comment syntax)
    doesn't confuse those simpler scanners."""
    text = _HERESTRING_DQ_RE.sub(_blank_span_preserving_newlines, text)
    text = _HERESTRING_SQ_RE.sub(_blank_span_preserving_newlines, text)
    return text


def _blank_block_comments(text: str) -> str:
    """Replace <# ... #> block comments with whitespace of the same shape:
    newlines/carriage-returns preserved (so line numbers stay aligned),
    everything else blanked."""
    return _BLOCK_COMMENT_RE.sub(_blank_span_preserving_newlines, text)


def _strip_line_comment(line: str) -> str:
    """Strip a trailing '#...' line comment, honoring simple single/double
    quoted string boundaries (including '' escaping inside single-quoted
    strings and `-escaping inside double-quoted strings) so a '#' that's
    part of a string literal isn't mistaken for a comment marker."""
    out = []
    in_single = in_double = False
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if in_single:
            out.append(c)
            if c == "'":
                if i + 1 < n and line[i + 1] == "'":
                    out.append(line[i + 1])
                    i += 2
                    continue
                in_single = False
            i += 1
            continue
        if in_double:
            out.append(c)
            if c == "`" and i + 1 < n:
                out.append(line[i + 1])
                i += 2
                continue
            if c == '"':
                in_double = False
            i += 1
            continue
        if c == "'":
            in_single = True
            out.append(c)
        elif c == '"':
            in_double = True
            out.append(c)
        elif c == "#":
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


def strip_comments_for_matching(text: str) -> List[str]:
    """Produce a comment-blanked, line-numbering-preserving version of the
    script, split into lines, used ONLY to drive detector matching (never
    shown to the user — `snippet` fields always come from the original
    text). Here-string bodies are blanked first, then block comments, then
    per-line trailing comments are stripped.

    Uses str.splitlines() here — the same method scan_text() uses to split
    the *original* text — rather than str.split("\\n"). A str.split("\\n")
    on text with a trailing newline (the overwhelmingly common case for
    real files) produces one extra empty trailing element that
    .splitlines() does not, which silently broke the line-count-equality
    fallback in scan_text() and defeated comment-stripping entirely on
    ordinary files during initial testing. splitlines() on both sides keeps
    them aligned."""
    blanked = _blank_herestrings(text)
    blanked = _blank_block_comments(blanked)
    return [_strip_line_comment(l) for l in blanked.splitlines()]


# --------------------------------------------------------------------------
# Shared vocabulary: cmdlets/aliases interesting to obfuscation detection
# --------------------------------------------------------------------------

# Cmdlets/aliases that, if reached indirectly (wildcard resolution, backtick
# splitting, case randomization, string concatenation, env-var assembly),
# represent a meaningful "arrival point" for obfuscated command execution.
DANGEROUS_TARGETS = [
    "invoke-expression", "iex",
    "invoke-restmethod", "irm",
    "invoke-webrequest", "iwr",
    "invoke-command", "icm",
    "downloadstring", "downloadfile", "downloaddata",
    "frombase64string",
]

# Cmdlet names we specifically watch for character-masking (backtick split /
# case randomization / concatenation). Kept to a deliberately small,
# high-signal set to avoid flagging every cmdlet's casing in the wild.
CANONICAL_WATCHLIST = [
    "Invoke-Expression",
    "Invoke-WebRequest",
    "Invoke-RestMethod",
    "Invoke-Command",
    "New-Object",
    "Add-Type",
    "Start-Process",
    "DownloadString",
    "DownloadFile",
    "DownloadData",
    "FromBase64String",
]


def _normalize(s: str) -> str:
    """Lowercase and strip everything but letters/digits, for fuzzy matching
    of reconstructed cmdlet names (backtick-stripped, concatenated, etc.)."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


_NORMALIZED_DANGEROUS = [(_normalize(t), t) for t in DANGEROUS_TARGETS]


def matches_dangerous_target(reconstructed: str) -> Optional[str]:
    """Given a reconstructed identifier (backtick-stripped, concatenated,
    de-homoglyphed, etc.), return the canonical dangerous target name it
    matches, or None. Short aliases (iex/irm/iwr/icm) require an exact
    match; longer cmdlet names are matched by substring containment so
    reconstructions with extra characters still hit."""
    norm = _normalize(reconstructed)
    if not norm:
        return None
    for norm_target, original in _NORMALIZED_DANGEROUS:
        if len(norm_target) <= 3:
            if norm == norm_target:
                return original
        else:
            if norm_target in norm or norm == norm_target:
                return original
    return None


# ==========================================================================
# Category 1 — Wildcard alias/command resolution feeding execution
# ==========================================================================
#
# The signature STEEP#MAVERICK pattern: Get-Alias / Get-Command invoked with
# a wildcard pattern instead of a literal cmdlet/alias name, so that the
# literal string "Invoke-Expression" / "iex" / "Invoke-RestMethod" / etc.
# never appears anywhere in the script. We can't run PowerShell's wildcard
# resolver, but we CAN apply the same glob semantics (`*` / `?`) that
# PowerShell's -like / Get-Command wildcard matching uses, via Python's
# fnmatch, against a list of dangerous targets. If the pattern used in the
# script *would* match one of those targets, that's a statically provable
# resolution path — not a guess.

_LOOKUP_CMDLET_RE = re.compile(r"(?i)\b(Get-Alias|gal|Get-Command|gcm)\b")
_WILDCARD_TOKEN_RE = re.compile(r"""['"]?([A-Za-z0-9*?][A-Za-z0-9*?\-]{0,40})['"]?""")


def find_wildcard_resolution(line: str) -> List[Tuple[str, str, bool]]:
    """Returns list of (cmdlet_used, wildcard_pattern, resolves_to_dangerous)."""
    results = []
    for m in _LOOKUP_CMDLET_RE.finditer(line):
        tail = line[m.end(): m.end() + 60]
        tail_scoped = re.split(r"[|;]", tail)[0]
        for tm in _WILDCARD_TOKEN_RE.finditer(tail_scoped):
            tok = tm.group(1)
            if "*" in tok or "?" in tok:
                dangerous = any(
                    fnmatch.fnmatchcase(target, tok.lower())
                    for target in DANGEROUS_TARGETS
                )
                results.append((m.group(1), tok, dangerous))
                break
    return results


_ASSIGN_RE = re.compile(r"^\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=")


def _var_invoked_nearby(lines: List[str], idx: int, varname: str, window: int = 3) -> bool:
    """Light cross-line correlation: does `& $varname` (or `$varname.Name`
    invoked via `&`) appear within `window` lines after idx? This is not
    real data-flow analysis — just a bounded lookahead to raise confidence
    when a wildcard-resolved handle is clearly being invoked."""
    pattern = re.compile(r"&\s*\$" + re.escape(varname) + r"\b")
    for j in range(idx + 1, min(idx + 1 + window, len(lines))):
        if pattern.search(lines[j]):
            return True
    return False


# 1b. Variable-indirect wildcard resolution — round-1 critique finding [HIGH,
# F1]: the literal-token-on-the-same-line check above is trivially defeated
# by a one-line refactor that stores the wildcard pattern in a variable
# first:
#     $pattern = 'i*x'
#     $resolved = Get-Alias -Name $pattern
# This is a bounded (not full data-flow) fix: look backward up to `window`
# lines from a `Get-Alias/Get-Command $var` call for a simple
# `$var = '<wildcard pattern>'` literal assignment to that same variable
# name, and resolve it the same way a same-line literal would be resolved.
_VAR_WILDCARD_ASSIGN_RE = re.compile(
    r"""^\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]([^'"]*[*?][^'"]*)['"]\s*$"""
)
_LOOKUP_VAR_ARG_RE = re.compile(
    r"(?i)\b(Get-Alias|gal|Get-Command|gcm)\b[^\n]{0,30}?\$([A-Za-z_][A-Za-z0-9_]*)\b"
)


def find_variable_indirect_wildcard(
    lines: List[str], idx: int, window: int = 6
) -> Optional[Tuple[str, str, str, int, bool]]:
    """Returns (cmdlet_used, varname, pattern, assign_lineno,
    resolves_to_dangerous) or None. Still bounded/approximate: computed or
    concatenated patterns, patterns assigned more than `window` lines
    earlier, or patterns passed in as function parameters are not resolved
    — documented as a residual gap in README.md/HANDOFF.md rather than
    silently claimed as covered."""
    line = lines[idx]
    m = _LOOKUP_VAR_ARG_RE.search(line)
    if not m:
        return None
    cmdlet_used, varname = m.group(1), m.group(2)
    for j in range(idx - 1, max(idx - 1 - window, -1), -1):
        am = _VAR_WILDCARD_ASSIGN_RE.match(lines[j])
        if am and am.group(1) == varname:
            pattern = am.group(2)
            dangerous = any(
                fnmatch.fnmatchcase(target, pattern.lower())
                for target in DANGEROUS_TARGETS
            )
            return (cmdlet_used, varname, pattern, j + 1, dangerous)
    return None


# ==========================================================================
# Category 2 — Character masking
# ==========================================================================

# 2a. Backtick-split identifiers: I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n
_BACKTICK_RUN_RE = re.compile(r"(?:[A-Za-z\-]`){3,}[A-Za-z\-]")


def find_backtick_masking(line: str) -> List[Tuple[str, str]]:
    """Returns list of (raw_match, reconstructed_identifier)."""
    out = []
    for m in _BACKTICK_RUN_RE.finditer(line):
        raw = m.group(0)
        reconstructed = raw.replace("`", "")
        out.append((raw, reconstructed))
    return out


# 2b. Case-randomized cmdlet names from the watchlist. We deliberately do
# NOT flag all-lowercase or ALL-UPPERCASE usage (both are extremely common
# and PowerShell is case-insensitive by design) — only genuinely mixed /
# alternating casing, which is a deliberate evasion technique against
# case-sensitive signature matching.
_WATCHLIST_RE = [
    (name, re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE))
    for name in CANONICAL_WATCHLIST
]


def _case_transitions(token: str) -> int:
    letters = [c for c in token if c.isalpha()]
    transitions = 0
    for a, b in zip(letters, letters[1:]):
        if a.islower() != b.islower():
            transitions += 1
    return transitions


def find_case_randomization(line: str) -> List[Tuple[str, str, str]]:
    """Returns list of (matched_token, canonical_name, confidence).

    Round-1 critique finding [HIGH, F3]: the original ">=2 case transitions"
    bar flagged `invoke-WebRequest` (lowercase first letter, otherwise
    perfect PascalCase — an extremely common human typo, not evasion) as
    HIGH. Fixed by requiring the mismatched casing to extend beyond just the
    first letter before flagging at all, and requiring a materially higher
    bar (3+ distinct mismatched positions AND 3+ case transitions) before
    calling it HIGH; a lighter but still-plausible-deliberate case (2+/2+)
    is capped at MEDIUM. A single leading-letter case slip is not flagged
    at any confidence — it's too common a typo shape to be useful signal.
    """
    out = []
    for canonical, rx in _WATCHLIST_RE:
        for m in rx.finditer(line):
            tok = m.group(0)
            if tok == canonical:
                continue
            if tok == tok.lower() or tok == tok.upper():
                continue  # simple casing, not "randomized" — too common to flag
            diff_positions = [
                idx for idx, (a, b) in enumerate(zip(tok, canonical))
                if a.isalpha() and a != b
            ]
            if not diff_positions or diff_positions == [0]:
                # No mismatch, or only the very first letter differs (the
                # classic "forgot to capitalize" typo) — don't flag.
                continue
            transitions = _case_transitions(tok)
            if transitions >= 3 and len(diff_positions) >= 3:
                out.append((tok, canonical, "HIGH"))
            elif transitions >= 2 and len(diff_positions) >= 2:
                out.append((tok, canonical, "MEDIUM"))
            # else: below the bar for "randomized" — too easily a typo, skip.
    return out


# 2c. String concatenation / reordering reconstructing a cmdlet name, e.g.
#     ('Inv' + 'oke-Exp' + 'ression')   or   ('I','n','v','o','k','e') -join ''
_CONCAT_PLUS_RE = re.compile(
    r"""(['"])(?:(?!\1).){1,30}\1(?:\s*\+\s*(['"])(?:(?!\2).){1,30}\2){1,}"""
)
_CONCAT_JOIN_RE = re.compile(
    r"""\(\s*(?:['"][^'"]*['"]\s*,\s*){2,}['"][^'"]*['"]\s*\)\s*-join\s*['"]{0,2}"""
)
_FRAGMENT_RE = re.compile(r"""(['"])((?:(?!\1).)*)\1""")


def find_string_reconstruction(line: str) -> List[Tuple[str, str, str]]:
    """Returns list of (raw_match, reconstructed, dangerous_target)."""
    out = []
    for rx in (_CONCAT_PLUS_RE, _CONCAT_JOIN_RE):
        for m in rx.finditer(line):
            raw = m.group(0)
            fragments = [fm.group(2) for fm in _FRAGMENT_RE.finditer(raw)]
            reconstructed = "".join(fragments)
            target = matches_dangerous_target(reconstructed)
            if target:
                out.append((raw, reconstructed, target))
    return out


# 2d. Unicode homoglyph substitution inside cmdlet-like identifiers.
# Small, high-confidence set of Cyrillic characters commonly used to spoof
# Latin lookalikes in phishing / obfuscation tooling. Presence of ANY of
# these mixed with ASCII letters in an identifier-shaped token is inherently
# suspicious — legitimate PowerShell source essentially never contains them.
_HOMOGLYPH_CHARS = set("аеорсхуіѕАЕОРСХУІЅ")  # Cyrillic lookalikes for Latin a e o p c x y i s
_IDENTIFIER_RE = re.compile(r"[A-Za-zЀ-ӿ][A-Za-zЀ-ӿ\-]{2,}")


def find_homoglyph_masking(line: str) -> List[Tuple[str, str]]:
    """Returns list of (token, delatinized_guess)."""
    out = []
    homoglyph_map = {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
        "і": "i", "ѕ": "s",
        "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "У": "Y",
        "І": "I", "Ѕ": "S",
    }
    for m in _IDENTIFIER_RE.finditer(line):
        tok = m.group(0)
        has_ascii = any(c.isascii() and c.isalpha() for c in tok)
        has_homoglyph = any(c in _HOMOGLYPH_CHARS for c in tok)
        if has_ascii and has_homoglyph:
            delatinized = "".join(homoglyph_map.get(c, c) for c in tok)
            out.append((tok, delatinized))
    return out


# 2e. Char-code array reconstruction — round-1 critique finding [HIGH, F2]:
# a cmdlet name built from an array of character codes cast via
# [char]/[char[]] and joined, e.g.
#     $codes = 73,110,118,101,120,101,45,69,120,112,114,101,115,115,105,111,110
#     $name = ($codes | ForEach-Object { [char]$_ }) -join ''
# Attacker code commonly defines the numeric array on one line and casts +
# joins it a line or two later, so this is a bounded (few-line) window
# check, not a strict single-line one.
_INT_ARRAY_RE = re.compile(r"(?:\b\d{1,3}\s*,\s*){2,}\b\d{1,3}\b")
_CHAR_CAST_RE = re.compile(r"(?i)\[char(?:\[\])?\]")
_JOIN_OP_RE = re.compile(r"(?i)-join\b")


def find_charcode_reconstruction(
    lines: List[str], idx: int, window: int = 3
) -> Optional[Tuple[str, str, str]]:
    """Returns (raw_array_text, reconstructed, dangerous_target) or None.
    Only fires when the decoded byte values actually spell out a known
    dangerous target — same "prove it, don't guess" approach used
    everywhere else in this tool, to keep the false-positive rate on
    ordinary numeric-array code (there's a lot of it — offsets, RGB values,
    byte buffers, etc.) at zero."""
    m = _INT_ARRAY_RE.search(lines[idx])
    if not m:
        return None
    block = "\n".join(lines[idx: min(idx + window, len(lines))])
    if not (_CHAR_CAST_RE.search(block) and _JOIN_OP_RE.search(block)):
        return None
    try:
        nums = [int(x) for x in re.split(r"\s*,\s*", m.group(0).strip(", "))]
    except ValueError:
        return None
    if len(nums) < 3 or not all(0 <= n <= 0x10FFFF for n in nums):
        return None
    try:
        reconstructed = "".join(chr(n) for n in nums)
    except ValueError:
        return None
    target = matches_dangerous_target(reconstructed)
    if not target:
        return None
    return (m.group(0), reconstructed, target)


# 2f. -f format-operator reconstruction — round-1 critique finding [HIGH,
# F2]: cmdlet name assembled via PowerShell's -f format operator instead of
# +/-join concatenation, e.g.
#     $name = '{0}{1}{2}' -f 'Inv','oke-Expr','ession'
# Capture the format string itself (group 1) as well as the argument list (group 2):
# the placeholder order is the whole point of this technique and reconstructing in
# argument order misses the reordered case entirely.
_FORMAT_OP_RE = re.compile(
    r"""(['"][^'"]*\{\d+\}[^'"]*['"])\s*-f\s*((?:['"][^'"]*['"]\s*,\s*)*['"][^'"]*['"])""",
    re.IGNORECASE,
)
_FMT_INDEX_RE = re.compile(r"\{(\d+)\}")


def find_format_operator_reconstruction(line: str) -> List[Tuple[str, str, str]]:
    """Returns list of (raw_match, reconstructed, dangerous_target).

    Honours the {N} placeholder order. Reconstructing in plain argument order misses
    the reordered form -- `"{1}{0}" -f 'EX','I'` rebuilds to 'IEX', not 'EXI' -- and
    that reordering is the entire trick, so a reconstruction that ignores it is blind
    to the most common variant in the wild.
    """
    out = []
    for m in _FORMAT_OP_RE.finditer(line):
        fmt, args_blob = m.group(1), m.group(2)
        fragments = [fm.group(2) for fm in _FRAGMENT_RE.finditer(args_blob)]
        order = [int(i) for i in _FMT_INDEX_RE.findall(fmt)]
        if order and all(i < len(fragments) for i in order):
            reconstructed = "".join(fragments[i] for i in order)
        else:
            reconstructed = "".join(fragments)
        target = matches_dangerous_target(reconstructed)
        if target:
            out.append((m.group(0), reconstructed, target))
    return out


# --------------------------------------------------------------------------
# Path-derived character harvesting
#
# Instead of masking a literal or wildcard-resolving a cmdlet name, this harvests
# individual characters out of some *other* string -- typically a filesystem path
# produced by a wildcard Resolve-Path -- and joins them into the cmdlet name:
#
#   .((rvpa "\???????\*2\*POO*\*river?\?6*").Path[4,15,34] -join '')
#
# Nothing in the script spells the target, no alias table is queried, and the
# character source is attacker-chosen, so neither the character-masking checks nor
# the wildcard-resolution checks above see it. The durable tell is an explicit
# integer index list into a string property, joined, in an invocation context.
# --------------------------------------------------------------------------

_PATH_RESOLVER_RE = re.compile(
    r"(?i)\b(resolve-path|rvpa|get-childitem|gci|get-item|gi|dir|ls|get-location|pwd)\b"
)
_INDEX_JOIN_RE = re.compile(
    r"(?i)\.\s*(path|fullname|name|basename|directoryname|directory|fullpath)\s*"
    r"\[\s*(\d+(?:\s*,\s*\d+)+)\s*\][^\n]{0,60}?-join"
)
# the same harvest applied to a bare string/variable rather than a path property
_BARE_INDEX_JOIN_RE = re.compile(r"\[\s*(\d+(?:\s*,\s*\d+){2,})\s*\][^\n]{0,60}?-join")
_CALL_OPERATOR_RE = re.compile(r"(?:^|[^\w`])[.&]\s*\(")


def find_path_char_harvest(line: str) -> List[Tuple[str, str, bool, bool]]:
    """Returns list of (raw_match, index_list, from_resolved_path, invoked)."""
    out = []
    invoked = bool(_CALL_OPERATOR_RE.search(line)) or bool(_PIPE_OR_IEX_RE.search(line))
    resolver = bool(_PATH_RESOLVER_RE.search(line))

    seen_spans = []
    for m in _INDEX_JOIN_RE.finditer(line):
        seen_spans.append(m.span())
        out.append((m.group(0), m.group(2), resolver, invoked))

    # bare indexing (no path property) needs 3+ indices to be worth reporting,
    # otherwise ordinary array slicing in benign scripts trips it
    for m in _BARE_INDEX_JOIN_RE.finditer(line):
        if any(s <= m.start() < e for s, e in seen_spans):
            continue
        out.append((m.group(0), m.group(1), resolver, invoked))
    return out


# ==========================================================================
# Category 3 — Environment-variable-based obfuscation
# ==========================================================================

_ENV_REF_RE = re.compile(r"(?i)\$env:[a-z0-9_]+")
_CURLY_SPLIT_RE = re.compile(r"(?:\$\{[A-Za-z0-9_:]{1,16}\}){2,}")
_INVOKE_OP_RE = re.compile(r"&\s*\$[A-Za-z_][A-Za-z0-9_]*\b")
_PIPE_OR_IEX_RE = re.compile(r"(?i)(\|\s*(iex|invoke-expression)\b|\biex\b|\binvoke-expression\b)")


def find_env_var_concat(line: str) -> Optional[Tuple[int, bool]]:
    """Returns (ref_count, immediate_execution_context) if 2+ $env: refs are
    combined with a '+' concatenation operator on the same line."""
    refs = _ENV_REF_RE.findall(line)
    if len(refs) >= 2 and "+" in line:
        immediate = bool(_INVOKE_OP_RE.search(line) or _PIPE_OR_IEX_RE.search(line))
        return (len(refs), immediate)
    return None


def find_curly_var_splitting(line: str) -> List[str]:
    return [m.group(0) for m in _CURLY_SPLIT_RE.finditer(line)]


# ==========================================================================
# Category 4 — Encoded command / download cradle
# ==========================================================================

_ENCODED_CMD_RE = re.compile(r"(?i)-enc(?:odedcommand)?\b")
_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_DECODE_RE = re.compile(r"(?i)frombase64string")
_IEX_RE = re.compile(r"(?i)\b(iex|invoke-expression)\b")
_PIPE_IEX_RE = re.compile(r"(?i)\|\s*(iex|invoke-expression)\b")
_WEBCLIENT_RE = re.compile(r"(?i)new-object\s+(?:-typename\s+)?(?:system\.)?net\.webclient")
_DOWNLOAD_METHOD_RE = re.compile(r"(?i)\.download(string|file|data)\s*\(")
_IWR_IRM_RE = re.compile(r"(?i)\b(invoke-webrequest|invoke-restmethod|iwr|irm)\b")


def find_encoded_command(line: str) -> bool:
    return bool(_ENCODED_CMD_RE.search(line))


def find_base64_execute_chain(line: str) -> bool:
    has_blob = bool(_B64_BLOB_RE.search(line))
    has_decode = bool(_DECODE_RE.search(line))
    has_exec = bool(_IEX_RE.search(line) or _PIPE_IEX_RE.search(line))
    return (has_blob or has_decode) and has_exec


def find_download_cradle(line: str) -> bool:
    has_downloader = bool(_WEBCLIENT_RE.search(line) or _IWR_IRM_RE.search(line))
    has_exec_chain = bool(
        _DOWNLOAD_METHOD_RE.search(line) or _IEX_RE.search(line) or _PIPE_IEX_RE.search(line)
    )
    return has_downloader and has_exec_chain


# ==========================================================================
# Orchestration
# ==========================================================================


def scan_text(text: str, filename: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = text.splitlines()

    # Detection runs against a comment-blanked copy of the text (see
    # `strip_comments_for_matching` docstring for why — round-1 critique
    # finding F4). `snippet` in reported findings still comes from the
    # original `lines` so output stays fully readable; only *matching* is
    # comment-blind-corrected. Defensive fallback: if comment-stripping
    # ever produces a different line count than the original split (exotic
    # Unicode line separators `splitlines()` recognizes but a plain '\n'
    # split does not), fall back to the original lines rather than risk
    # misaligned line numbers.
    match_lines = strip_comments_for_matching(text)
    if len(match_lines) != len(lines):
        match_lines = lines

    for i, line in enumerate(lines):
        lineno = i + 1
        snippet = _truncate(line)
        m_line = match_lines[i]

        # --- Category 1: wildcard alias/command resolution (literal) ---
        for cmdlet_used, pattern, dangerous in find_wildcard_resolution(m_line):
            if dangerous:
                confidence = "HIGH"
                rationale = (
                    f"'{cmdlet_used}' invoked with wildcard pattern '{pattern}' — "
                    f"applying PowerShell's own wildcard semantics, this pattern "
                    f"statically resolves to a dangerous target (matches known "
                    f"alias/cmdlet in {DANGEROUS_TARGETS!r}). This is the STEEP#MAVERICK "
                    f"wildcard-IEX invocation pattern that motivated T1027.010."
                )
            else:
                assign = _ASSIGN_RE.match(m_line)
                escalate = False
                if assign:
                    escalate = _var_invoked_nearby(match_lines, i, assign.group(1))
                confidence = "MEDIUM" if escalate else "LOW"
                rationale = (
                    f"'{cmdlet_used}' invoked with wildcard pattern '{pattern}'. "
                    f"Pattern does not statically match a known dangerous target, "
                    f"but wildcard-based command resolution is itself the technique "
                    f"primitive covered by T1027.010"
                    + (" and the resolved handle is invoked via '&' nearby." if escalate else ".")
                )
            findings.append(Finding(
                file=filename, line=lineno, category="wildcard-resolution",
                label="Wildcard alias/command resolution feeding execution",
                snippet=snippet, confidence=confidence, rationale=rationale,
            ))

        # --- Category 1b: wildcard alias/command resolution (variable-indirect) ---
        vi = find_variable_indirect_wildcard(match_lines, i)
        if vi:
            cmdlet_used, varname, pattern, assign_lineno, dangerous = vi
            if dangerous:
                confidence = "HIGH"
                rationale = (
                    f"'{cmdlet_used} ... ${varname}' resolves indirectly: ${varname} "
                    f"was assigned the wildcard pattern '{pattern}' on line "
                    f"{assign_lineno}, which statically resolves to a dangerous "
                    f"target via the same wildcard-semantics check used for literal "
                    f"patterns. Storing the pattern in a variable one line earlier "
                    f"does not defeat this check."
                )
            else:
                assign2 = _ASSIGN_RE.match(m_line)
                escalate = bool(assign2 and _var_invoked_nearby(match_lines, i, assign2.group(1)))
                confidence = "MEDIUM" if escalate else "LOW"
                rationale = (
                    f"'{cmdlet_used} ... ${varname}' resolves indirectly via "
                    f"${varname}, assigned wildcard pattern '{pattern}' on line "
                    f"{assign_lineno}. Pattern does not statically match a known "
                    f"dangerous target."
                    + (" Resolved handle is invoked via '&' nearby." if escalate else "")
                )
            findings.append(Finding(
                file=filename, line=lineno, category="wildcard-resolution",
                label="Wildcard alias/command resolution feeding execution (variable-indirect)",
                snippet=snippet, confidence=confidence, rationale=rationale,
            ))

        # --- Category 2a: backtick masking ---
        for raw, reconstructed in find_backtick_masking(m_line):
            raw_t = _truncate(raw, 120)
            recon_t = _truncate(reconstructed, 120)
            target = matches_dangerous_target(reconstructed)
            if target:
                confidence = "HIGH"
                rationale = (
                    f"Backtick-split identifier '{raw_t}' reconstructs (stripping "
                    f"backticks) to '{recon_t}', which matches known dangerous "
                    f"target '{target}'."
                )
            else:
                confidence = "MEDIUM"
                rationale = (
                    f"Backtick-split identifier '{raw_t}' reconstructs to "
                    f"'{recon_t}'. Backtick-splitting of identifiers is a "
                    f"character-masking technique regardless of target."
                )
            findings.append(Finding(
                file=filename, line=lineno, category="character-masking-backtick",
                label="Character masking: backtick-split cmdlet name",
                snippet=snippet, confidence=confidence, rationale=rationale,
            ))

        # --- Category 2b: case randomization ---
        for tok, canonical, cr_confidence in find_case_randomization(m_line):
            findings.append(Finding(
                file=filename, line=lineno, category="character-masking-case",
                label="Character masking: case-randomized cmdlet name",
                snippet=snippet, confidence=cr_confidence,
                rationale=(
                    f"'{tok}' is a case-randomized rendering of '{canonical}' "
                    f"(PowerShell resolves it identically; the irregular casing exists "
                    f"only to defeat case-sensitive literal-string signatures)."
                ),
            ))

        # --- Category 2c: string concatenation / reordering ---
        for raw, reconstructed, target in find_string_reconstruction(m_line):
            findings.append(Finding(
                file=filename, line=lineno, category="character-masking-concat",
                label="Character masking: string concatenation reconstructs cmdlet name",
                snippet=snippet, confidence="HIGH",
                rationale=(
                    f"String fragments in '{_truncate(raw, 80)}' concatenate to "
                    f"'{_truncate(reconstructed, 80)}', matching known dangerous "
                    f"target '{target}'."
                ),
            ))

        # --- Category 2d: Unicode homoglyph masking ---
        for tok, delatinized in find_homoglyph_masking(m_line):
            findings.append(Finding(
                file=filename, line=lineno, category="character-masking-homoglyph",
                label="Character masking: Unicode homoglyph substitution",
                snippet=snippet, confidence="HIGH",
                rationale=(
                    f"Token '{_truncate(tok, 80)}' mixes ASCII letters with non-Latin "
                    f"homoglyph character(s); Latinized reading is "
                    f"'{_truncate(delatinized, 80)}'. Legitimate PowerShell source "
                    f"essentially never mixes scripts like this."
                ),
            ))

        # --- Category 2e: char-code array reconstruction ---
        cc = find_charcode_reconstruction(match_lines, i)
        if cc:
            raw_array, reconstructed, target = cc
            findings.append(Finding(
                file=filename, line=lineno, category="character-masking-charcode",
                label="Character masking: char-code array reconstructs cmdlet name",
                snippet=snippet, confidence="HIGH",
                rationale=(
                    f"Integer array '{_truncate(raw_array, 100)}' cast via [char] and "
                    f"joined nearby decodes to '{_truncate(reconstructed, 80)}', "
                    f"matching known dangerous target '{target}'."
                ),
            ))

        # --- Category 2f: -f format-operator reconstruction ---
        for raw, reconstructed, target in find_format_operator_reconstruction(m_line):
            findings.append(Finding(
                file=filename, line=lineno, category="character-masking-format-op",
                label="Character masking: -f format-operator reconstructs cmdlet name",
                snippet=snippet, confidence="HIGH",
                rationale=(
                    f"Format-operator expression '{_truncate(raw, 100)}' assembles "
                    f"'{_truncate(reconstructed, 80)}', matching known dangerous "
                    f"target '{target}'."
                ),
            ))

        for raw, idxs, from_path, invoked in find_path_char_harvest(m_line):
            n = len([i for i in idxs.split(",") if i.strip()])
            if from_path and invoked:
                conf = "HIGH"
            elif from_path or invoked:
                conf = "MEDIUM"
            else:
                conf = "LOW"
            src = ("a wildcard-resolved filesystem path" if from_path
                   else "a string value")
            findings.append(Finding(
                file=filename, line=lineno, category="path-char-harvest",
                label="Character harvesting: indexed characters joined into a command name",
                snippet=snippet, confidence=conf,
                rationale=(
                    f"Expression '{_truncate(raw, 100)}' picks {n} characters at fixed "
                    f"offsets [{idxs}] out of {src} and joins them"
                    + (", and the result is invoked directly. " if invoked else ". ")
                    + "The command name is never written anywhere in the script and no "
                      "alias table is queried, so neither literal matching nor "
                      "Get-Alias/Get-Command heuristics will see it."
                ),
            ))

        # --- Category 3: environment-variable obfuscation ---
        env_result = find_env_var_concat(m_line)
        if env_result:
            ref_count, immediate = env_result
            confidence = "HIGH" if immediate else "MEDIUM"
            rationale = (
                f"{ref_count} distinct $env: references concatenated with '+' to "
                f"build a command string"
                + (", and the result is invoked/piped directly." if immediate else ".")
            )
            findings.append(Finding(
                file=filename, line=lineno, category="env-var-obfuscation",
                label="Environment-variable-based command string reconstruction",
                snippet=snippet, confidence=confidence, rationale=rationale,
            ))

        for raw in find_curly_var_splitting(m_line):
            findings.append(Finding(
                file=filename, line=lineno, category="env-var-obfuscation",
                label="Environment-variable-based command string reconstruction",
                snippet=snippet, confidence="MEDIUM",
                rationale=(
                    f"Adjacent '${{...}}' variable-splitting syntax "
                    f"'{_truncate(raw, 100)}' used to assemble a string from "
                    f"fragments; a common way to build a command name piecewise "
                    f"without a literal substring match."
                ),
            ))

        # --- Category 4: encoded command / download cradle ---
        if find_encoded_command(m_line):
            findings.append(Finding(
                file=filename, line=lineno, category="encoded-command",
                label="Encoded command invocation (-EncodedCommand/-enc)",
                snippet=snippet, confidence="HIGH",
                rationale=(
                    "Use of -EncodedCommand/-enc smuggles a Base64/UTF-16LE encoded "
                    "script past line-based content inspection; PowerShell decodes "
                    "and runs it at process start."
                ),
            ))

        if find_base64_execute_chain(m_line):
            findings.append(Finding(
                file=filename, line=lineno, category="base64-execute-chain",
                label="Base64-decoded payload piped into execution",
                snippet=snippet, confidence="HIGH",
                rationale=(
                    "Base64 blob and/or FromBase64String() decode combined with "
                    "IEX/Invoke-Expression on the same line — classic decode-and-run "
                    "chain."
                ),
            ))

        if find_download_cradle(m_line):
            findings.append(Finding(
                file=filename, line=lineno, category="download-cradle",
                label="Download-and-execute cradle",
                snippet=snippet, confidence="HIGH",
                rationale=(
                    "Net.WebClient / Invoke-WebRequest / Invoke-RestMethod download "
                    "method combined with an execution sink (IEX/pipe) on the same "
                    "line — fetches remote content and runs it without touching disk."
                ),
            ))

    return findings


# --------------------------------------------------------------------------
# File I/O helpers
# --------------------------------------------------------------------------


def read_text_file(path: Path) -> str:
    """Best-effort text decode. PowerShell scripts on Windows are often
    UTF-16LE with a BOM; 4104 log exports are usually UTF-8. Try common
    encodings before falling back to a lossy latin-1 read. Never executes
    or interprets the content — this is a pure decode-to-text step."""
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-16", "utf-8"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return raw.decode("latin-1", errors="replace")


def collect_files(root: Path) -> List[Path]:
    if root.is_file():
        return [root]
    files: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in EXTENSIONS:
                files.append(p)
    return sorted(files)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def print_text_report(findings: List[Finding], files_scanned: List[Path], min_confidence: str) -> None:
    if not findings:
        print(f"No T1027.010 indicators found at or above confidence '{min_confidence}' "
              f"across {len(files_scanned)} file(s) scanned.")
        return

    by_file: dict = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    for filename, items in by_file.items():
        print(f"\n=== {filename} ===")
        for finding in sorted(items, key=lambda x: x.line):
            print(f"  [{finding.confidence}] line {finding.line} "
                  f"— {finding.label}  ({finding.technique_id} / parent {finding.parent_id})")
            print(f"    snippet : {finding.snippet}")
            print(f"    why     : {finding.rationale}")

    high = sum(1 for f in findings if f.confidence == "HIGH")
    medium = sum(1 for f in findings if f.confidence == "MEDIUM")
    low = sum(1 for f in findings if f.confidence == "LOW")
    print("\n--- summary ---")
    print(f"files scanned : {len(files_scanned)}")
    print(f"findings      : {len(findings)}  (HIGH={high} MEDIUM={medium} LOW={low})")
    by_cat: dict = {}
    for f in findings:
        by_cat[f.label] = by_cat.get(f.label, 0) + 1
    for label, count in sorted(by_cat.items(), key=lambda kv: -kv[1]):
        print(f"  {count:3d}  {label}")
    print(f"\nATT&CK: {TECHNIQUE_ID} ({TECHNIQUE_NAME}) — {TECHNIQUE_URL}")
    print(f"        parent {PARENT_ID} ({PARENT_NAME}) — {PARENT_URL}")


def print_json_report(findings: List[Finding], files_scanned: List[Path]) -> None:
    payload = {
        "tool": "t1027010_hunter",
        "technique": {
            "id": TECHNIQUE_ID, "name": TECHNIQUE_NAME, "url": TECHNIQUE_URL,
            "parent_id": PARENT_ID, "parent_name": PARENT_NAME, "parent_url": PARENT_URL,
        },
        "files_scanned": [str(p) for p in files_scanned],
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    print(json.dumps(payload, indent=2))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="t1027010_hunter.py",
        description=(
            "Static analysis hunter for MITRE ATT&CK T1027.010 (Command Obfuscation) "
            "indicators in PowerShell source or exported Event ID 4104 Script Block "
            "Log text. Read-only text/regex analysis; never executes input content."
        ),
    )
    parser.add_argument(
        "path",
        help="File or directory to scan. Directories are walked recursively for "
             f"{', '.join(sorted(EXTENSIONS))} files.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit findings as JSON instead of the human-readable text report.",
    )
    parser.add_argument(
        "--min-confidence", choices=["low", "medium", "high"], default="low",
        help="Only report findings at or above this confidence level (default: low).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    files = collect_files(root)
    if not files:
        print(f"error: no scannable files found under {root} "
              f"(looked for {', '.join(sorted(EXTENSIONS))})", file=sys.stderr)
        return 2

    all_findings: List[Finding] = []
    for path in files:
        try:
            text = read_text_file(path)
        except Exception as exc:  # pragma: no cover - defensive I/O guard
            print(f"warning: could not read {path}: {exc}", file=sys.stderr)
            continue
        all_findings.extend(scan_text(text, str(path)))

    min_rank = CONFIDENCE_ORDER[args.min_confidence]
    filtered = [f for f in all_findings if CONFIDENCE_ORDER[f.confidence.lower()] >= min_rank]

    if args.json:
        print_json_report(filtered, files)
    else:
        print_text_report(filtered, files, args.min_confidence)

    return 1 if any(f.confidence == "HIGH" for f in filtered) else 0


if __name__ == "__main__":
    sys.exit(main())
