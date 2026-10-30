"""Produce redacted copies of a Document in its original format, using exact finding offsets."""

from __future__ import annotations

import csv
import io
from copy import deepcopy
from dataclasses import dataclass
from typing import Collection, Dict, List, Sequence
from xml.sax.saxutils import escape

from .models import Document, Finding
from .parsers import iter_docx_paragraphs

MIME = {
    "txt": "text/plain", "md": "text/markdown", "markdown": "text/markdown", "csv": "text/csv",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pdf": "application/pdf",
}


@dataclass
class RedactionResult:
    name: str
    mime: str
    data: bytes
    applied: int


def replacement_label(finding: Finding) -> str:
    return f"[REDACTED:{finding.category.placeholder}]"


def redacted_segment_texts(doc: Document, findings: Sequence[Finding]) -> Dict[int, str]:
    """Return {segment_index: new_text} for segments touched by the given (non-overlapping) findings."""
    ordered = sorted((f for f in findings if f.located), key=lambda f: f.start)
    updates: Dict[int, str] = {}
    for index, segment in enumerate(doc.segments):
        pieces, cursor, changed = [], 0, False
        for finding in ordered:
            if finding.end <= segment.start or finding.start >= segment.end:
                continue
            local_start = max(finding.start - segment.start, 0)
            local_end = min(finding.end - segment.start, len(segment.text))
            pieces.append(segment.text[cursor:local_start])
            if finding.start >= segment.start:  # label goes where the finding begins
                pieces.append(replacement_label(finding))
            cursor, changed = local_end, True
        if changed:
            pieces.append(segment.text[cursor:])
            updates[index] = "".join(pieces)
    return updates


def redact_document(
    doc: Document,
    findings: Sequence[Finding],
    selected_ids: Collection[str],
    drop_columns: Collection[int] = (),
) -> RedactionResult:
    chosen = [f for f in findings if f.finding_id in selected_ids and f.located]
    updates = redacted_segment_texts(doc, chosen)
    writer = _WRITERS.get(doc.fmt)
    if writer is None:
        raise ValueError(f"Cannot write redacted copies of '{doc.fmt}' documents.")
    data = writer(doc, updates, sorted(set(drop_columns)))
    return RedactionResult(name=f"redacted_{doc.name}", mime=MIME[doc.fmt], data=data, applied=len(chosen))


# ----------------------------------------------------------------------------- writers
def _write_text(doc: Document, updates: Dict[int, str], _drop: List[int]) -> bytes:
    return updates.get(0, doc.segments[0].text).encode("utf-8")


def _write_csv(doc: Document, updates: Dict[int, str], drop: List[int]) -> bytes:
    rows = [list(row) for row in doc.meta["rows"]]
    for index, text in updates.items():
        _, r, c = doc.segments[index].ref
        rows[r][c] = text
    rows = [[cell for c, cell in enumerate(row) if c not in drop] for row in rows]
    out = io.StringIO()
    csv.writer(out, delimiter=doc.meta["delimiter"], lineterminator="\n").writerows(rows)
    return out.getvalue().encode("utf-8")


def _write_docx(doc: Document, updates: Dict[int, str], _drop: List[int]) -> bytes:
    from docx import Document as OpenDocx

    document = OpenDocx(io.BytesIO(doc.raw))
    new_text = {doc.segments[i].ref[1]: text for i, text in updates.items()}
    for position, paragraph in enumerate(iter_docx_paragraphs(document)):
        if position not in new_text:
            continue
        first_run = paragraph.runs[0]._r if paragraph.runs else None
        run_format = deepcopy(first_run.rPr) if first_run is not None and first_run.rPr is not None else None
        paragraph.clear()  # also removes hyperlink elements that hold the original text
        run = paragraph.add_run(new_text[position])
        if run_format is not None:
            run._r.insert(0, run_format)
    props = document.core_properties
    props.author = props.last_modified_by = props.comments = ""
    out = io.BytesIO()
    document.save(out)
    return out.getvalue()


def _write_pdf(doc: Document, updates: Dict[int, str], _drop: List[int]) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

    style = getSampleStyleSheet()["BodyText"]
    story = []
    for index, segment in enumerate(doc.segments):
        if story:
            story.append(PageBreak())
        for line in updates.get(index, segment.text).splitlines() or [""]:
            story.append(Paragraph(escape(line) or "&nbsp;", style))
        story.append(Spacer(1, 6))
    out = io.BytesIO()
    SimpleDocTemplate(out, pagesize=A4, title="Redacted copy", author="").build(story)
    return out.getvalue()


_WRITERS = {
    "txt": _write_text, "md": _write_text, "markdown": _write_text,
    "csv": _write_csv, "docx": _write_docx, "pdf": _write_pdf,
}
