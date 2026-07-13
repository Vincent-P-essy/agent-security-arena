from __future__ import annotations

import base64
import binascii
import hashlib
import re
from html.parser import HTMLParser
from io import BytesIO

from pypdf import PdfReader
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject

from agent_security_arena.models import ExtractionRecord, ScenarioInput

MAX_DOCUMENT_BYTES = 1_048_576
MAX_EXTRACTED_CHARACTERS = 200_000
MAX_PDF_PAGES = 20
PDF_ACTIVE_TOKEN = re.compile(
    rb"/(?:AA|EmbeddedFiles?|JavaScript|JS|Launch|OpenAction|RichMedia)(?=[\s/<>()\[\]])"
)
PDF_ACTIVE_NAMES = {
    "/AA",
    "/EmbeddedFile",
    "/EmbeddedFiles",
    "/JavaScript",
    "/JS",
    "/Launch",
    "/OpenAction",
    "/RichMedia",
}
MAX_PDF_OBJECTS = 10_000
HTML_VOID_ELEMENTS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}


class DocumentExtractionError(ValueError):
    pass


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _normalize_text(value: str) -> str:
    normalized = "\n".join(line.strip() for line in value.replace("\x00", "").splitlines())
    normalized = re.sub(r"[ \t]+", " ", normalized)
    normalized = re.sub(r"\n{3,}", "\n\n", normalized).strip()
    if len(normalized) > MAX_EXTRACTED_CHARACTERS:
        raise DocumentExtractionError("extracted document text exceeds the configured limit")
    return normalized


class _SafeHTMLExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.fragments: list[str] = []
        self._hidden_stack: list[bool] = []
        self.hidden_fragments = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): (value or "") for name, value in attrs}
        style = attributes.get("style", "").lower().replace(" ", "")
        hidden = (
            tag.lower() in {"script", "style", "template"}
            or "hidden" in attributes
            or attributes.get("aria-hidden", "").lower() == "true"
            or "display:none" in style
            or "visibility:hidden" in style
            or "opacity:0" in style
        )
        if tag.lower() not in HTML_VOID_ELEMENTS:
            self._hidden_stack.append(hidden or any(self._hidden_stack))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, _tag: str) -> None:
        if self._hidden_stack:
            self._hidden_stack.pop()

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if not text:
            return
        if any(self._hidden_stack):
            self.fragments.append(f"[hidden] {text}")
            self.hidden_fragments += 1
        else:
            self.fragments.append(text)

    def handle_comment(self, data: str) -> None:
        text = data.strip()
        if text:
            self.fragments.append(f"[comment] {text}")
            self.hidden_fragments += 1


class DocumentExtractor:
    def extract(self, value: ScenarioInput) -> ExtractionRecord:
        raw = self._decode(value)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise DocumentExtractionError("document exceeds the 1 MiB input limit")

        hidden_fragments = 0
        pages = 0
        warnings: list[str] = []
        if value.content_type == "html":
            parser = _SafeHTMLExtractor()
            try:
                parser.feed(raw.decode("utf-8", errors="strict"))
                parser.close()
            except (UnicodeDecodeError, ValueError) as exc:
                raise DocumentExtractionError("HTML document is not valid UTF-8") from exc
            text = _normalize_text("\n".join(parser.fragments))
            hidden_fragments = parser.hidden_fragments
        elif value.content_type == "pdf":
            text, pages, warnings = self._extract_pdf(raw)
        else:
            try:
                text = _normalize_text(raw.decode("utf-8", errors="strict"))
            except UnicodeDecodeError as exc:
                raise DocumentExtractionError("text document is not valid UTF-8") from exc

        return ExtractionRecord(
            content_type=value.content_type,
            input_bytes=len(raw),
            input_sha256=_sha256(raw),
            text=text,
            text_sha256=_sha256(text.encode("utf-8")),
            hidden_fragments=hidden_fragments,
            pages=pages,
            warnings=warnings,
        )

    @staticmethod
    def _decode(value: ScenarioInput) -> bytes:
        if value.content_encoding == "plain":
            try:
                return value.untrusted_content.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise DocumentExtractionError("text document cannot be encoded as UTF-8") from exc
        try:
            return base64.b64decode(value.untrusted_content, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise DocumentExtractionError("document is not valid base64") from exc

    @staticmethod
    def _extract_pdf(raw: bytes) -> tuple[str, int, list[str]]:
        if not raw.startswith(b"%PDF-"):
            raise DocumentExtractionError("PDF signature is missing")
        if PDF_ACTIVE_TOKEN.search(raw):
            raise DocumentExtractionError("PDF contains an active-content feature")
        try:
            reader = PdfReader(BytesIO(raw), strict=True)
            if reader.is_encrypted:
                raise DocumentExtractionError("encrypted PDFs are not accepted")
            if DocumentExtractor._contains_active_pdf_object(reader.trailer):
                raise DocumentExtractionError("PDF contains an active-content feature")
            if len(reader.pages) > MAX_PDF_PAGES:
                raise DocumentExtractionError("PDF exceeds the page limit")
            extracted: list[str] = []
            warnings: list[str] = []
            for index, page in enumerate(reader.pages):
                page_text = page.extract_text() or ""
                if not page_text.strip():
                    warnings.append(f"page {index + 1} contains no extractable text")
                extracted.append(page_text)
        except DocumentExtractionError:
            raise
        except Exception as exc:
            raise DocumentExtractionError("PDF parsing failed") from exc
        return _normalize_text("\n".join(extracted)), len(reader.pages), warnings

    @staticmethod
    def _contains_active_pdf_object(root: object) -> bool:
        stack = [root]
        visited: set[tuple[int, int] | int] = set()
        inspected = 0
        while stack:
            value = stack.pop()
            inspected += 1
            if inspected > MAX_PDF_OBJECTS:
                raise DocumentExtractionError("PDF object graph exceeds the configured limit")
            if isinstance(value, IndirectObject):
                identity: tuple[int, int] | int = (value.idnum, value.generation)
                if identity in visited:
                    continue
                visited.add(identity)
                stack.append(value.get_object())
            elif isinstance(value, DictionaryObject):
                if any(str(key) in PDF_ACTIVE_NAMES for key in value):
                    return True
                identity = id(value)
                if identity in visited:
                    continue
                visited.add(identity)
                stack.extend(value.values())
            elif isinstance(value, ArrayObject):
                stack.extend(value)
        return False
