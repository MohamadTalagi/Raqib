from unittest.mock import MagicMock, patch

import httpx

from remediation_engine import build_prompt, call_gemini, generate_remediation_blueprint

FINDING = {
    "control_id": "SA-IOT-002",
    "control_title": "No default or hard-coded credentials",
    "requirement_text": "Prevent the users from using default and hard-coded passwords.",
    "status": "FAIL",
    "severity": "high",
    "reason_or_finding": "observations.default_creds equals True",
    "device_label": "device-insecure (Insecure Smart Camera)",
    "existing_remediation": "Force a unique strong password on first boot.",
}


def _mock_response(status_code=200, json_body=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_body
    if status_code >= 400:
        response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "http error", request=MagicMock(), response=response
        )
    else:
        response.raise_for_status.return_value = None
    return response


def _gemini_success_body(priority="immediate"):
    return {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": (
                                '{"root_cause": "Default credentials were never rotated.", '
                                '"remediation_steps": ["Force a password change on first boot.", '
                                '"Disable the default account after setup."], '
                                f'"priority": "{priority}", "estimated_effort": "Low - config change only.", '
                                '"caveats": "Confirm no other services rely on the default account."}'
                            )
                        }
                    ]
                }
            }
        ]
    }


# -- build_prompt -------------------------------------------------------


def test_build_prompt_includes_the_finding_details_and_structured_schema():
    body = build_prompt(FINDING)
    text = body["contents"][0]["parts"][0]["text"]
    assert "SA-IOT-002" in text
    assert "default and hard-coded passwords" in text
    assert "device-insecure" in text
    assert "do not invent" in text.lower() or "invent" in text.lower()
    assert body["generationConfig"]["responseMimeType"] == "application/json"
    assert "priority" in body["generationConfig"]["responseSchema"]["properties"]


def test_build_prompt_handles_a_missing_device_label_for_org_scope_findings():
    org_finding = {**FINDING, "device_label": None}
    body = build_prompt(org_finding)
    text = body["contents"][0]["parts"][0]["text"]
    assert "organization-wide" in text


# -- call_gemini / generate_remediation_blueprint ------------------------


@patch("remediation_engine.httpx.post")
def test_call_gemini_returns_none_when_no_api_key_configured(mock_post, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    result = call_gemini(build_prompt(FINDING))
    assert result is None
    mock_post.assert_not_called()


@patch("remediation_engine.httpx.post")
def test_call_gemini_parses_a_successful_response(mock_post, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    mock_post.return_value = _mock_response(200, _gemini_success_body())

    result = call_gemini(build_prompt(FINDING))

    assert result["priority"] == "immediate"
    assert result["remediation_steps"] == [
        "Force a password change on first boot.",
        "Disable the default account after setup.",
    ]
    call_kwargs = mock_post.call_args.kwargs
    assert call_kwargs["params"]["key"] == "test-key"


@patch("remediation_engine.httpx.post")
def test_call_gemini_returns_none_on_http_error_never_raises(mock_post, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    mock_post.return_value = _mock_response(429)

    assert call_gemini(build_prompt(FINDING)) is None


@patch("remediation_engine.httpx.post")
def test_call_gemini_returns_none_on_malformed_json_in_the_text_part(mock_post, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    mock_post.return_value = _mock_response(200, {
        "candidates": [{"content": {"parts": [{"text": "not valid json"}]}}]
    })

    assert call_gemini(build_prompt(FINDING)) is None


@patch("remediation_engine.httpx.post")
def test_call_gemini_returns_none_when_a_required_field_is_missing(mock_post, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    mock_post.return_value = _mock_response(200, {
        "candidates": [{"content": {"parts": [{"text": '{"root_cause": "x"}'}]}}]
    })

    assert call_gemini(build_prompt(FINDING)) is None


@patch("remediation_engine.httpx.post")
def test_call_gemini_returns_none_when_priority_is_not_a_valid_value(mock_post, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    mock_post.return_value = _mock_response(200, _gemini_success_body(priority="urgent!!"))

    assert call_gemini(build_prompt(FINDING)) is None


@patch("remediation_engine.httpx.post")
def test_call_gemini_returns_none_on_a_network_exception(mock_post, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    mock_post.side_effect = httpx.ConnectError("connection refused")

    assert call_gemini(build_prompt(FINDING)) is None


@patch("remediation_engine.httpx.post")
def test_generate_remediation_blueprint_end_to_end(mock_post, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    mock_post.return_value = _mock_response(200, _gemini_success_body())

    result = generate_remediation_blueprint(FINDING)

    assert result["root_cause"] == "Default credentials were never rotated."
