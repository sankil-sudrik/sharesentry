"""Turn uploaded bytes into a `Document` of addressable segments.

Parsing never raises for expected problems (bad type, oversize, scanned PDF, encrypted file);
it returns a Document whose `incomplete_reasons` explains what could not be inspected.
"""

from __future__ import annotations

import csv
import io
from pathlib import PurePath
from typing import Iterator, Tuple

from .models import Document

SUPPORTED = ("txt", "md", "markdown", "csv", "docx", "pdf")
CSV_DELIMITERS = ",;\t|"
DOCX_NOTE = (
    "DOCX comments, tracked changes, embedded objects, hyperlink targets and file metadata "
    "are not inspected. Document properties (author, last modified by) are cleared in redacted copies."
)


def extension(name: str) -> str:
    return PurePath(name).suffix.lower().lstrip(".")


def decode_text(data: bytes) -> Tuple[str, str]:
    """Decode bytes to text. Returns (text, encoding_used)."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16"), "utf-16"
    try:
        return data.decode("utf-8-sig"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "latin-1"


def parse_document(name: str, data: bytes, max_bytes: int) -> Document:
    ext = extension(name)
    doc = Document(name=name or "document", fmt="markdown" if ext == "markdown" else ext, raw=data)
    if ext not in SUPPORTED:
        doc.fmt = ext or "unknown"
        doc.incomplete_reasons.append(f"Unsupported file type '.{ext}'. Supported: txt, md, csv, docx, pdf.")
        return doc
    if len(data) > max_bytes:
        doc.incomplete_reasons.append(f"File is {len(data) / 1_048_576:.1f} MB; the limit is {max_bytes / 1_048_576:.0f} MB.")
        return doc
    if not data.strip():
        doc.incomplete_reasons.append("The file is empty.")
        return doc
    {"txt": _parse_text, "md": _parse_text, "markdown": _parse_text,
     "csv": _parse_csv, "docx": _parse_docx, "pdf": _parse_pdf}[ext](doc)
    if not doc.segments and not doc.incomplete_reasons:
        doc.incomplete_reasons.append("No extractable text was found.")
    return doc


# ----------------------------------------------------------------------------- text / markdown
def _parse_text(doc: Document) -> None:
    text, encoding = decode_text(doc.raw)
    doc.meta["encoding"] = encoding
    if encoding == "latin-1":
        doc.scope_notes.append("The file is not valid UTF-8; it was read as Latin-1, so some characters may be misread.")
    doc.set_segments([(text, ("text",))] if text.strip() else [])


# ----------------------------------------------------------------------------- csv
def _parse_csv(doc: Document) -> None:
    text, encoding = decode_text(doc.raw)
    doc.meta["encoding"] = encoding
    try:
        delimiter = csv.Sniffer().sniff(text[:4096], delimiters=CSV_DELIMITERS).delimiter
    except csv.Error:
        delimiter = ","
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter))
    except csv.Error as exc:
        doc.incomplete_reasons.append(f"The CSV could not be parsed: {exc}")
        return
    doc.meta.update(rows=rows, delimiter=delimiter)
    doc.set_segments([
        (cell, ("csv", r, c))
        for r, row in enumerate(rows)
        for c, cell in enumerate(row)
        if cell.strip()
    ])


# ----------------------------------------------------------------------------- docx
def iter_docx_paragraphs(document) -> Iterator:
    """Yield every distinct paragraph (body, tables, headers, footers) in a stable order."""
    seen = set()

    def walk(container) -> Iterator:
        for paragraph in container.paragraphs:
            if id(paragraph._p) not in seen:
                seen.add(id(paragraph._p))
                yield paragraph
        for table in getattr(container, "tables", []):
            for row in table.rows:
                for cell in row.cells:
                    yield from walk(cell)

    yield from walk(document)
    for section in document.sections:
        for part in (section.header, section.footer):
            if not part.is_linked_to_previous:  # touching a linked part would create it
                yield from walk(part)


def _parse_docx(doc: Document) -> None:
    from docx import Document as OpenDocx

    if not doc.raw.startswith(b"PK"):
        doc.incomplete_reasons.append("The file is not a valid DOCX (it is not a ZIP container).")
        return
    try:
        document = OpenDocx(io.BytesIO(doc.raw))
        paragraphs = [p.text for p in iter_docx_paragraphs(document)]
    except Exception as exc:  # python-docx raises several unrelated types for corrupt files
        doc.incomplete_reasons.append(f"The DOCX could not be read: {type(exc).__name__}.")
        return
    doc.scope_notes.append(DOCX_NOTE)
    doc.set_segments([(text, ("docx", i)) for i, text in enumerate(paragraphs) if text.strip()])


# ----------------------------------------------------------------------------- pdf
def _parse_pdf(doc: Document) -> None:
    from pypdf import PdfReader

    if not doc.raw.startswith(b"%PDF"):
        doc.incomplete_reasons.append("The file is not a valid PDF.")
        return
    try:
        reader = PdfReader(io.BytesIO(doc.raw))
        if reader.is_encrypted and not reader.decrypt(""):
            doc.incomplete_reasons.append("The PDF is password-protected and could not be opened.")
            return
        pages = [(page.extract_text() or "") for page in reader.pages]
    except Exception as exc:
        doc.incomplete_reasons.append(f"The PDF could not be read: {type(exc).__name__}.")
        return
    empty = [str(i + 1) for i, text in enumerate(pages) if not text.strip()]
    if empty:
        doc.incomplete_reasons.append(
            f"Page(s) {', '.join(empty)} have no extractable text (scanned or image-only); they were not inspected."
        )
    doc.meta["page_count"] = len(pages)
    doc.scope_notes.append("PDF images, annotations and metadata are not inspected.")
    doc.set_segments([(text, ("pdf", i)) for i, text in enumerate(pages) if text.strip()])
