"""Write scan report and fixed TF/CDK code to disk."""

import json
import re
from pathlib import Path

from iac_scanner.orchestration.runner import PipelineResult


def _parse_fixed_files(fixed_code: str) -> list[tuple[str, str]]:
    """Parse ---FILE: path --- blocks into (path, content) list. Single block = one entry."""
    out: list[tuple[str, str]] = []
    pattern = re.compile(r"---FILE:\s*([^\n-]+)---\s*\n([\s\S]*?)(?=---FILE:|$)", re.MULTILINE)
    for m in pattern.finditer(fixed_code):
        path, content = m.group(1).strip(), m.group(2).strip()
        out.append((path, content))
    if not out:
        out.append(("", fixed_code.strip()))
    return out


def _split_by_scan_headers(
    fixed_code: str,
    metadata_files: list[str],
    base_path: Path,
    iac_type: str,
) -> list[tuple[str, str]]:
    """
    When the model returns the same section headers as the scan (e.g. // --- index.ts ---),
    split and map each section to the correct relative path so we write all files (e.g. lib/demo-stack.ts).
    """
    base_path = Path(base_path).resolve()
    name_to_rel: dict[str, Path] = {}
    for p in metadata_files:
        path = Path(p).resolve()
        try:
            rel = path.relative_to(base_path)
            name_to_rel[path.name] = rel
        except ValueError:
            name_to_rel[path.name] = Path(path.name)

    # Capture filename (may contain hyphens, e.g. demo-stack.ts) until " ---"
    if iac_type == "cdk":
        header_re = re.compile(r"(?:^|\n)// --- (.+?) ---\n", re.MULTILINE)
    else:
        header_re = re.compile(r"(?:^|\n)# --- (.+?) ---\n", re.MULTILINE)

    matches = list(header_re.finditer(fixed_code))
    if not matches:
        return []

    parts: list[tuple[str, str]] = []
    for i, m in enumerate(matches):
        name = m.group(1).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(fixed_code)
        content = fixed_code[start:end].rstrip()
        rel_path = name_to_rel.get(name, name)
        parts.append((str(rel_path), content))
    return parts


def write_report_and_fixes(
    result: PipelineResult,
    output_dir: str | Path,
    *,
    report_name: str = "scan-report.json",
    write_fixed: bool = True,
) -> list[Path]:
    """
    Write scan report (JSON) and fixed code files to output_dir.
    Returns list of written paths.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    report_path = output_dir / report_name
    report = {
        "iac_type": result.scan_result.iac_type,
        "entry_path": str(result.scan_result.entry_path),
        "findings": result.findings_list,
        "findings_raw": result.findings_raw,
        "metadata": result.scan_result.metadata,
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    written.append(report_path)

    if write_fixed and result.fixed_code:
        base = result.scan_result.entry_path.parent
        parsed = _parse_fixed_files(result.fixed_code)
        metadata_files = result.scan_result.metadata.get("files") or []

        # If model returned one block but we have multiple source files, split by scan headers (// --- file --- or # --- file ---)
        if len(parsed) == 1 and not parsed[0][0] and len(metadata_files) > 1:
            by_headers = _split_by_scan_headers(
                result.fixed_code,
                metadata_files,
                base,
                result.scan_result.iac_type,
            )
            if by_headers:
                parsed = by_headers

        for rel_path, content in parsed:
            if rel_path:
                out_path = output_dir / "fixed" / rel_path
            else:
                out_path = output_dir / "fixed" / result.scan_result.entry_path.name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(content, encoding="utf-8")
            written.append(out_path)

    return written
