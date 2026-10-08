"""Unified diff parsing and line position mapping for PR review comments.

Implements Section 3.6.3 of the architecture document:
- Parses unified diff hunk headers (@@ -old,count +new,count @@).
- Maps findings to diff line positions (line, start_line, side).
- Multi-line findings place the comment on line_end with start_line set.
- Findings on context-only lines map to the nearest modified line in the hunk,
  updating the explanation to note the actual affected line.
- Findings outside all diff hunks are marked is_in_diff=False for summary-only display.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence

from codepulse.aggregation.models import Finding

HUNK_HEADER_REGEX = re.compile(
    r"^@@\s+-(?P<old_start>\d+)(?:,(?P<old_count>\d+))?\s+\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))?\s+@@"
)
FILE_HEADER_REGEX = re.compile(r"^\+\+\+\s+[b/]?(?P<path>\S+)")


@dataclass
class DiffHunk:
    """Represents a single parsed diff hunk for a specific file."""

    new_start: int
    new_count: int
    modified_lines: set[int] = field(default_factory=set)  # '+' lines
    context_lines: set[int] = field(default_factory=set)   # ' ' lines

    @property
    def all_lines(self) -> set[int]:
        return self.modified_lines | self.context_lines


@dataclass
class FileDiff:
    """Represents all hunks for a specific file in the diff."""

    path: str
    hunks: list[DiffHunk] = field(default_factory=list)


def parse_unified_diff(diff_text: str) -> dict[str, FileDiff]:
    """Parse unified diff text into per-file hunk models.

    Args:
        diff_text: Full raw unified diff text.

    Returns:
        Dictionary mapping normalized file paths to FileDiff instances.
    """
    file_diffs: dict[str, FileDiff] = {}
    current_file: str | None = None
    current_hunk: DiffHunk | None = None
    current_new_line = 0

    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            # Example: "+++ b/src/app.py" or "+++ src/app.py"
            raw_path = line[4:].strip().split("\t")[0].split(" ")[0]
            if raw_path.startswith("b/") or raw_path.startswith("a/"):
                normalized_path = raw_path[2:]
            else:
                normalized_path = raw_path
            current_file = normalized_path.lstrip("/")
            if current_file not in file_diffs:
                file_diffs[current_file] = FileDiff(path=current_file)
            current_hunk = None
            continue

        if line.startswith("--- "):
            current_hunk = None
            continue

        if line.startswith("@@"):
            match = HUNK_HEADER_REGEX.match(line)
            if match and current_file:
                new_start = int(match.group("new_start"))
                new_count = int(match.group("new_count") or "1")
                current_hunk = DiffHunk(new_start=new_start, new_count=new_count)
                file_diffs[current_file].hunks.append(current_hunk)
                current_new_line = new_start
            else:
                current_hunk = None
            continue

        if current_hunk is not None:
            if line.startswith("+"):
                current_hunk.modified_lines.add(current_new_line)
                current_new_line += 1
            elif line.startswith(" "):
                current_hunk.context_lines.add(current_new_line)
                current_new_line += 1
            elif line.startswith("-"):
                # Deleted line: does not advance new file line counter
                pass

    return file_diffs


def map_findings_to_diff_positions(
    findings: Sequence[Finding],
    diff_text: str,
) -> list[Finding]:
    """Map findings to their corresponding diff line positions.

    Modifies finding instances in-place with diff_line, diff_start_line,
    diff_side, and is_in_diff.

    Args:
        findings: Sequence of unified Finding instances.
        diff_text: Unified diff string.

    Returns:
        List of findings with diff position attributes updated.
    """
    file_diffs = parse_unified_diff(diff_text)
    mapped_findings: list[Finding] = []

    for f in findings:
        lookup_path = f.file_path.lstrip("/")
        file_diff = file_diffs.get(lookup_path) or file_diffs.get(f.file_path)
        if not file_diff:
            # File is not present in diff at all
            f.is_in_diff = False
            f.diff_line = None
            f.diff_start_line = None
            mapped_findings.append(f)
            continue

        target_line = f.line_end
        matched_hunk: DiffHunk | None = None

        # Check if line falls in any hunk
        for hunk in file_diff.hunks:
            if target_line in hunk.all_lines or f.line_start in hunk.all_lines:
                matched_hunk = hunk
                break

        if not matched_hunk:
            # Line is outside all hunks
            f.is_in_diff = False
            f.diff_line = None
            f.diff_start_line = None
            mapped_findings.append(f)
            continue

        f.is_in_diff = True
        f.diff_side = "RIGHT"

        if target_line in matched_hunk.modified_lines:
            # Direct hit on a modified line
            f.diff_line = target_line
            if f.line_start < f.line_end and f.line_start in matched_hunk.all_lines:
                f.diff_start_line = f.line_start
            else:
                f.diff_start_line = None
        elif target_line in matched_hunk.context_lines:
            # Context-only line: map to nearest modified line in the same hunk
            if matched_hunk.modified_lines:
                nearest_line = min(
                    matched_hunk.modified_lines,
                    key=lambda mod_line: abs(mod_line - target_line),
                )
                f.diff_line = nearest_line
                f.diff_start_line = None
                note = f"\n\n*(Note: This issue affects line {target_line}, placed on nearest changed line {nearest_line}.)*"
                if note not in f.explanation:
                    f.explanation += note
            else:
                f.is_in_diff = False
                f.diff_line = None
        else:
            # Fallback for line_start matching
            if f.line_start in matched_hunk.modified_lines:
                f.diff_line = f.line_start
                f.diff_start_line = None
            else:
                f.is_in_diff = False
                f.diff_line = None

        mapped_findings.append(f)

    return mapped_findings
