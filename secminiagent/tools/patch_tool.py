from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any

from .base import BaseTool, ToolContext, ToolError, ToolResult, truncate_text
from .file_tools import resolve_workspace_path


HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(slots=True)
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FilePatch:
    old_path: str | None
    new_path: str | None
    hunks: list[Hunk] = field(default_factory=list)


class ApplyPatchTool(BaseTool):
    name = "apply_patch"
    description = "Apply a unified diff patch to files inside the workspace."
    read_only = False
    input_schema = {
        "type": "object",
        "required": ["patch"],
        "properties": {
            "patch": {"type": "string"},
            "dry_run": {"type": "boolean", "default": False},
        },
    }

    async def execute(self, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        patches = parse_unified_patch(str(arguments["patch"]))
        dry_run = bool(arguments.get("dry_run", False))
        changed: list[str] = []
        rendered_diffs: list[str] = []
        for file_patch in patches:
            if file_patch.old_path and file_patch.new_path and file_patch.old_path != file_patch.new_path:
                raise ToolError("Renames are not supported by apply_patch.")
            raw_target = file_patch.new_path or file_patch.old_path
            if raw_target is None:
                raise ToolError("Patch file target is missing.")
            target = resolve_workspace_path(context.cwd, raw_target)
            rel_target = str(target.relative_to(context.cwd))

            old_text = ""
            old_lines: list[str] = []
            if file_patch.old_path is not None:
                if not target.exists():
                    raise ToolError(f"File does not exist: {rel_target}")
                old_text = target.read_text(encoding="utf-8", errors="replace")
                old_lines = old_text.splitlines()

            new_lines = apply_hunks(old_lines, file_patch.hunks, rel_target)
            old_label = "/dev/null" if file_patch.old_path is None else f"a/{rel_target}"
            new_label = "/dev/null" if file_patch.new_path is None else f"b/{rel_target}"
            rendered = "\n".join(
                difflib.unified_diff(old_lines, new_lines, fromfile=old_label, tofile=new_label, lineterm="")
            )
            rendered_diffs.append(rendered or f"No textual change for {rel_target}.")

            if not dry_run:
                if file_patch.new_path is None:
                    target.unlink()
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(lines_to_text(new_lines, old_text), encoding="utf-8")
            changed.append(rel_target)
        action = "Dry run succeeded" if dry_run else "Applied patch"
        return ToolResult(
            True,
            truncate_text(f"{action} for {len(changed)} file(s): {', '.join(changed)}\n\n" + "\n\n".join(rendered_diffs), context.max_output_chars),
            {"changed_files": changed, "dry_run": dry_run},
        )


def parse_unified_patch(patch_text: str) -> list[FilePatch]:
    lines = patch_text.splitlines()
    patches: list[FilePatch] = []
    index = 0
    while index < len(lines):
        if not lines[index].startswith("--- "):
            index += 1
            continue
        old_path = parse_patch_path(lines[index][4:])
        index += 1
        if index >= len(lines) or not lines[index].startswith("+++ "):
            raise ToolError("Unified diff is missing +++ file header.")
        new_path = parse_patch_path(lines[index][4:])
        file_patch = FilePatch(old_path=old_path, new_path=new_path)
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.startswith("--- "):
                break
            if not line.startswith("@@ "):
                index += 1
                continue
            match = HUNK_RE.match(line)
            if not match:
                raise ToolError(f"Invalid hunk header: {line}")
            hunk = Hunk(
                old_start=int(match.group(1)),
                old_count=int(match.group(2) or "1"),
                new_start=int(match.group(3)),
                new_count=int(match.group(4) or "1"),
            )
            index += 1
            while index < len(lines):
                hunk_line = lines[index]
                if hunk_line.startswith("@@ ") or hunk_line.startswith("--- "):
                    break
                if hunk_line.startswith("\\ No newline"):
                    index += 1
                    continue
                if not hunk_line or hunk_line[0] not in {" ", "+", "-"}:
                    raise ToolError(f"Invalid hunk line: {hunk_line}")
                hunk.lines.append(hunk_line)
                index += 1
            file_patch.hunks.append(hunk)
        if not file_patch.hunks:
            raise ToolError("Patch file has no hunks.")
        patches.append(file_patch)
    if not patches:
        raise ToolError("No unified diff file headers found.")
    return patches


def parse_patch_path(raw_path: str) -> str | None:
    path = raw_path.strip().split("\t", 1)[0]
    if path == "/dev/null":
        return None
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    if not path:
        raise ToolError("Patch path is empty.")
    return path


def apply_hunks(old_lines: list[str], hunks: list[Hunk], file_label: str) -> list[str]:
    result: list[str] = []
    source_index = 0
    for hunk in hunks:
        hunk_start = max(0, hunk.old_start - 1)
        if hunk_start < source_index:
            raise ToolError(f"Overlapping hunk in {file_label}.")
        result.extend(old_lines[source_index:hunk_start])
        source_index = hunk_start
        for hunk_line in hunk.lines:
            op = hunk_line[0]
            content = hunk_line[1:]
            if op == " ":
                require_line(old_lines, source_index, content, file_label)
                result.append(content)
                source_index += 1
            elif op == "-":
                require_line(old_lines, source_index, content, file_label)
                source_index += 1
            elif op == "+":
                result.append(content)
    result.extend(old_lines[source_index:])
    return result


def require_line(old_lines: list[str], index: int, expected: str, file_label: str) -> None:
    if index >= len(old_lines):
        raise ToolError(f"Patch context exceeded file length in {file_label}.")
    actual = old_lines[index]
    if actual != expected:
        raise ToolError(f"Patch context mismatch in {file_label} at line {index + 1}: expected {expected!r}, found {actual!r}.")


def lines_to_text(lines: list[str], old_text: str) -> str:
    if not lines:
        return ""
    newline = "\n" if old_text.endswith("\n") or old_text == "" else ""
    return "\n".join(lines) + newline
