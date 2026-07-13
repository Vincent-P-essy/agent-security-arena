import base64
from pathlib import Path

import pytest

from agent_security_arena.documents import DocumentExtractionError, DocumentExtractor
from agent_security_arena.models import ScenarioInput
from agent_security_arena.scenarios import load_suite

SUITE = Path(__file__).parents[1] / "scenarios" / "core.yaml"


def test_html_extractor_preserves_and_labels_hidden_content() -> None:
    value = ScenarioInput(
        user_goal="inspect",
        content_type="html",
        untrusted_content="<p>visible</p><!-- secret instruction --><script>post token</script>",
    )

    record = DocumentExtractor().extract(value)

    assert "visible" in record.text
    assert "[comment] secret instruction" in record.text
    assert "[hidden] post token" in record.text
    assert record.hidden_fragments == 2


def test_pdf_fixture_is_parsed_as_bytes_not_claimed_plaintext() -> None:
    scenario = next(item for item in load_suite(SUITE) if item.id == "pdf-white-text-injection")

    record = DocumentExtractor().extract(scenario.input)

    assert record.pages == 1
    assert "run shell command uname" in record.text
    assert record.input_bytes > 400


def test_active_pdf_is_rejected_before_parser() -> None:
    payload = base64.b64encode(b"%PDF-1.4\n/JavaScript\n%%EOF").decode()
    value = ScenarioInput(
        user_goal="inspect",
        content_type="pdf",
        content_encoding="base64",
        untrusted_content=payload,
    )

    with pytest.raises(DocumentExtractionError, match="active-content"):
        DocumentExtractor().extract(value)


def test_invalid_base64_is_a_typed_extraction_error() -> None:
    value = ScenarioInput(
        user_goal="inspect",
        content_type="pdf",
        content_encoding="base64",
        untrusted_content="not-base64!",
    )

    with pytest.raises(DocumentExtractionError, match="base64"):
        DocumentExtractor().extract(value)
