"""
=========================================================
SCAMSHIELD AI - INTELLIGENCE AGENT TEST SUITE
=========================================================

Tests:
    1. Agent initialization and metadata
    2. Supported evidence types
    3. Indicator extraction
    4. URL, phone, email and UPI extraction
    5. Indicator normalization
    6. Duplicate removal
    7. Suspicious keyword normalization
    8. Existing indicator reuse
    9. Indicator counts and summary
    10. Input validation
    11. Extractor failure handling
    12. Verification and privacy guarantees
    13. Error response integrity
    14. Public function testing

=========================================================
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

    
import pytest

from unittest.mock import Mock

from agents.intelligence_agent import (
    IntelligenceAgent,
    run_intelligence_analysis,
)


# =========================================================
# TEST FIXTURES
# =========================================================

class FakeExtractor:

    def __init__(
        self,
        response=None,
        exception=None,
    ):

        self.response = response

        self.exception = exception

        self.call_count = 0

        self.last_evidence = None

    def extract(self, evidence):

        self.call_count += 1

        self.last_evidence = evidence

        if self.exception:

            raise self.exception

        return self.response


@pytest.fixture
def sample_indicators():

    return {

        "success": True,

        "indicators": {

            "urls": [
                "https://example.com",
            ],

            "phone_numbers": [
                "+919876543210",
            ],

            "emails": [
                "test@example.com",
            ],

            "upi_ids": [
                "test@okaxis",
            ],

        },

        "suspicious_keywords": {

            "urgency": [
                "immediately",
            ],

            "financial": [
                "payment",
            ],

        },

    }


@pytest.fixture
def extractor(sample_indicators):

    return FakeExtractor(
        response=sample_indicators
    )


@pytest.fixture
def agent(extractor):

    return IntelligenceAgent(
        extractor=extractor
    )


# =========================================================
# INITIALIZATION TESTS
# =========================================================

def test_agent_initialization():

    agent = IntelligenceAgent()

    assert agent is not None


def test_agent_name(agent):

    assert agent.AGENT_NAME == "IntelligenceAgent"


def test_agent_version(agent):

    assert agent.AGENT_VERSION == "1.1.0"


def test_maximum_evidence_length(agent):

    assert agent.MAX_EVIDENCE_LENGTH == 20000


def test_extractor_initialization(agent):

    assert agent.extractor is not None


def test_custom_extractor_injection(extractor):

    agent = IntelligenceAgent(
        extractor=extractor
    )

    assert agent.extractor is extractor


# =========================================================
# SUPPORTED EVIDENCE TYPES
# =========================================================

@pytest.mark.parametrize(
    "evidence_type",
    [
        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",
    ],
)
def test_supported_evidence_types(
    agent,
    evidence_type,
):

    result = agent.analyze(
        evidence="Suspicious content",
        evidence_type=evidence_type,
    )

    assert result["success"] is True

    assert result["evidence_type"] == evidence_type


def test_evidence_type_normalization(agent):

    result = agent.analyze(
        evidence="Suspicious content",
        evidence_type=" MESSAGE ",
    )

    assert result["success"] is True

    assert result["evidence_type"] == "message"


# =========================================================
# BASIC ANALYSIS TESTS
# =========================================================

def test_normal_analysis(agent):

    result = agent.analyze(
        evidence="Please verify your account."
    )

    assert result["success"] is True


def test_analysis_id_generated(agent):

    result = agent.analyze(
        evidence="Suspicious message"
    )

    assert result["analysis_id"]


def test_analysis_id_is_string(agent):

    result = agent.analyze(
        evidence="Suspicious message"
    )

    assert isinstance(
        result["analysis_id"],
        str,
    )


def test_agent_metadata(agent):

    result = agent.analyze(
        evidence="Suspicious message"
    )

    assert result["agent"]["name"] == "IntelligenceAgent"

    assert result["agent"]["version"] == "1.1.0"

    assert result["agent"]["status"] == "completed"


def test_result_contains_intelligence(agent):

    result = agent.analyze(
        evidence="Suspicious message"
    )

    assert "intelligence" in result


def test_result_contains_summary(agent):

    result = agent.analyze(
        evidence="Suspicious message"
    )

    assert "summary" in result


def test_result_contains_indicator_counts(agent):

    result = agent.analyze(
        evidence="Suspicious message"
    )

    assert "indicator_counts" in result


def test_result_contains_verification(agent):

    result = agent.analyze(
        evidence="Suspicious message"
    )

    assert "verification" in result


def test_result_contains_metadata(agent):

    result = agent.analyze(
        evidence="Suspicious message"
    )

    assert "metadata" in result


# =========================================================
# INDICATOR EXTRACTION TESTS
# =========================================================

def test_url_extraction(agent):

    result = agent.analyze(
        evidence="Visit https://example.com"
    )

    assert result["intelligence"]["urls"] == [
        "https://example.com"
    ]


def test_phone_number_extraction(agent):

    result = agent.analyze(
        evidence="Call +919876543210"
    )

    assert result["intelligence"]["phone_numbers"] == [
        "+919876543210"
    ]


def test_email_extraction(agent):

    result = agent.analyze(
        evidence="Contact test@example.com"
    )

    assert result["intelligence"]["emails"] == [
        "test@example.com"
    ]


def test_upi_extraction(agent):

    result = agent.analyze(
        evidence="Send payment to test@okaxis"
    )

    assert result["intelligence"]["upi_ids"] == [
        "test@okaxis"
    ]


def test_all_indicator_types_extracted(agent):

    result = agent.analyze(
        evidence="Suspicious message"
    )

    intelligence = result["intelligence"]

    assert len(intelligence["urls"]) == 1

    assert len(intelligence["phone_numbers"]) == 1

    assert len(intelligence["emails"]) == 1

    assert len(intelligence["upi_ids"]) == 1


def test_extractor_called_once(agent, extractor):

    agent.analyze(
        evidence="Suspicious message"
    )

    assert extractor.call_count == 1


def test_extractor_receives_validated_evidence(
    agent,
    extractor,
):

    agent.analyze(
        evidence="  Suspicious message  "
    )

    assert extractor.last_evidence == "Suspicious message"


# =========================================================
# INDICATOR NORMALIZATION TESTS
# =========================================================

def test_empty_indicator_response():

    extractor = FakeExtractor(
        response={
            "success": True,
            "indicators": {},
        }
    )

    agent = IntelligenceAgent(extractor)

    result = agent.analyze(
        evidence="Normal message"
    )

    assert result["success"] is True

    assert result["indicator_counts"]["urls"] == 0


def test_direct_indicator_dictionary():

    extractor = FakeExtractor(
        response={

            "success": True,

            "urls": [
                "https://direct.example",
            ],

            "phone_numbers": [
                "9876543210",
            ],

        }
    )

    agent = IntelligenceAgent(extractor)

    result = agent.analyze(
        evidence="Test evidence"
    )

    assert result["success"] is True

    assert result["intelligence"]["urls"] == [
        "https://direct.example"
    ]


def test_links_alias():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "indicators": {
                    "links": [
                        "https://alias.example",
                    ],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["urls"] == [
        "https://alias.example"
    ]


def test_phones_alias():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "indicators": {
                    "phones": [
                        "9876543210",
                    ],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["phone_numbers"] == [
        "9876543210"
    ]


def test_email_addresses_alias():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "indicators": {
                    "email_addresses": [
                        "test@example.com",
                    ],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["emails"] == [
        "test@example.com"
    ]


def test_upi_alias():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "indicators": {
                    "upi": [
                        "user@okaxis",
                    ],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["upi_ids"] == [
        "user@okaxis"
    ]


# =========================================================
# DEDUPLICATION TESTS
# =========================================================

@pytest.mark.parametrize(
    "field",
    [
        "urls",
        "phone_numbers",
        "emails",
        "upi_ids",
    ],
)
def test_duplicate_indicators_removed(field):

    values = {
        "urls": [
            "https://example.com",
            "https://example.com",
        ],
        "phone_numbers": [
            "9876543210",
            "9876543210",
        ],
        "emails": [
            "test@example.com",
            "test@example.com",
        ],
        "upi_ids": [
            "test@okaxis",
            "test@okaxis",
        ],
    }

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "indicators": values,
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert len(
        result["intelligence"][field]
    ) == 1


def test_whitespace_duplicates_removed():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "indicators": {
                    "emails": [
                        " test@example.com ",
                        "test@example.com",
                    ],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["emails"] == [
        "test@example.com"
    ]


def test_indicator_order_preserved():

    urls = [
        "https://first.example",
        "https://second.example",
        "https://third.example",
    ]

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "indicators": {
                    "urls": urls,
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["urls"] == urls


# =========================================================
# INVALID INDICATOR VALUE TESTS
# =========================================================

@pytest.mark.parametrize(
    "invalid_value",
    [
        None,
        123,
        45.5,
        True,
        False,
        {},
    ],
)
def test_invalid_indicator_values_ignored(
    invalid_value,
):

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "indicators": {
                    "urls": invalid_value,
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["success"] is True

    assert result["intelligence"]["urls"] == []


def test_non_string_indicator_items_ignored():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "indicators": {
                    "urls": [
                        "https://valid.example",
                        None,
                        123,
                        True,
                    ],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["urls"] == [
        "https://valid.example"
    ]


def test_empty_indicator_strings_ignored():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "indicators": {
                    "urls": [
                        "",
                        "   ",
                        "https://valid.example",
                    ],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["urls"] == [
        "https://valid.example"
    ]


# =========================================================
# SUSPICIOUS KEYWORD TESTS
# =========================================================

def test_suspicious_keyword_extraction():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "suspicious_keywords": {
                    "urgency": [
                        "immediately",
                        "urgent",
                    ],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert "urgency" in result[
        "intelligence"
    ]["suspicious_keywords"]


def test_multiple_keyword_categories():

    keywords = {
        "urgency": ["immediately"],
        "financial": ["payment"],
        "threat": ["account blocked"],
    }

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "suspicious_keywords": keywords,
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert len(
        result["intelligence"]["suspicious_keywords"]
    ) == 3


def test_keyword_string_normalization():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "suspicious_keywords": {
                    "urgency": "immediately",
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["suspicious_keywords"][
        "urgency"
    ] == ["immediately"]


def test_keyword_list_normalization():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "suspicious_keywords": [
                    "urgent",
                    "payment",
                ],
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["suspicious_keywords"] == {
        "general": [
            "urgent",
            "payment",
        ]
    }


def test_keyword_duplicates_removed():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "suspicious_keywords": {
                    "urgency": [
                        "urgent",
                        "urgent",
                        "immediately",
                    ],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["suspicious_keywords"][
        "urgency"
    ] == [
        "urgent",
        "immediately",
    ]


def test_invalid_keyword_items_ignored():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "suspicious_keywords": {
                    "urgency": [
                        "urgent",
                        None,
                        123,
                    ],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["suspicious_keywords"][
        "urgency"
    ] == ["urgent"]


def test_empty_keyword_category_ignored():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "suspicious_keywords": {
                    "": ["urgent"],
                    "   ": ["payment"],
                    "valid": ["warning"],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["suspicious_keywords"] == {
        "valid": ["warning"]
    }


def test_invalid_keyword_container_ignored():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "suspicious_keywords": 123,
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["intelligence"]["suspicious_keywords"] == {}


# =========================================================
# EXISTING INDICATOR REUSE TESTS
# =========================================================

def test_existing_indicators_reused():

    extractor = FakeExtractor(
        response={
            "success": True,
            "indicators": {},
        }
    )

    agent = IntelligenceAgent(extractor)

    existing = {
        "urls": [
            "https://existing.example",
        ],
    }

    result = agent.analyze(
        evidence="Test evidence",
        existing_indicators=existing,
    )

    assert result["success"] is True

    assert result["metadata"]["indicators_reused"] is True

    assert extractor.call_count == 0


def test_existing_indicators_preserved():

    existing = {
        "urls": [
            "https://existing.example",
        ],
        "emails": [
            "existing@example.com",
        ],
    }

    agent = IntelligenceAgent()

    result = agent.analyze(
        evidence="Test evidence",
        existing_indicators=existing,
    )

    assert result["intelligence"]["urls"] == [
        "https://existing.example"
    ]

    assert result["intelligence"]["emails"] == [
        "existing@example.com"
    ]


def test_existing_indicators_deduplicated():

    existing = {
        "urls": [
            "https://example.com",
            "https://example.com",
        ],
    }

    agent = IntelligenceAgent()

    result = agent.analyze(
        evidence="Test evidence",
        existing_indicators=existing,
    )

    assert result["intelligence"]["urls"] == [
        "https://example.com"
    ]


def test_existing_indicators_invalid_type():

    agent = IntelligenceAgent()

    result = agent.analyze(
        evidence="Test evidence",
        existing_indicators=["invalid"],
    )

    assert result["success"] is False

    assert result["error"]["code"] == "invalid_input"


def test_existing_indicators_empty_dictionary():

    agent = IntelligenceAgent()

    result = agent.analyze(
        evidence="Test evidence",
        existing_indicators={},
    )

    assert result["success"] is True

    assert result["metadata"]["indicators_reused"] is True


# =========================================================
# SUMMARY AND COUNT TESTS
# =========================================================

def test_indicator_counts(agent):

    result = agent.analyze("Test evidence")

    counts = result["indicator_counts"]

    assert counts["urls"] == 1

    assert counts["phone_numbers"] == 1

    assert counts["emails"] == 1

    assert counts["upi_ids"] == 1

    assert counts["suspicious_keywords"] == 2


def test_total_indicator_count(agent):

    result = agent.analyze("Test evidence")

    assert result["summary"]["total_indicators"] == 6


def test_summary_message_with_indicators(agent):

    result = agent.analyze("Test evidence")

    assert result["summary"]["message"] == (
        "Intelligence indicators extracted successfully."
    )


def test_summary_message_without_indicators():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "indicators": {},
            }
        )
    )

    result = agent.analyze("Normal message")

    assert result["summary"]["total_indicators"] == 0

    assert result["summary"]["message"] == (
        "No supported intelligence indicators were detected."
    )


def test_keyword_count_uses_match_count():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "suspicious_keywords": {
                    "urgency": [
                        "urgent",
                        "immediately",
                        "quickly",
                    ],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["indicator_counts"][
        "suspicious_keywords"
    ] == 3


# =========================================================
# INPUT VALIDATION TESTS
# =========================================================

@pytest.mark.parametrize(
    "evidence",
    [
        "",
        "   ",
        "\n",
        "\t",
    ],
)
def test_empty_evidence_rejected(agent, evidence):

    result = agent.analyze(evidence)

    assert result["success"] is False

    assert result["error"]["code"] == "invalid_input"


@pytest.mark.parametrize(
    "evidence",
    [
        None,
        123,
        45.5,
        True,
        False,
        [],
        {},
    ],
)
def test_non_string_evidence_rejected(agent, evidence):

    result = agent.analyze(evidence)

    assert result["success"] is False

    assert result["error"]["code"] == "invalid_input"


def test_maximum_evidence_length(agent):

    result = agent.analyze(
        evidence="A" * 20000
    )

    assert result["success"] is True


def test_evidence_exceeding_maximum_length(agent):

    result = agent.analyze(
        evidence="A" * 20001
    )

    assert result["success"] is False

    assert result["error"]["code"] == "invalid_input"


@pytest.mark.parametrize(
    "evidence_type",
    [
        "",
        "invalid",
        "unknown",
        "image",
        "video",
        "audio",
    ],
)
def test_unsupported_evidence_type(
    agent,
    evidence_type,
):

    result = agent.analyze(
        evidence="Test evidence",
        evidence_type=evidence_type,
    )

    assert result["success"] is False

    assert result["error"]["code"] == "invalid_input"


@pytest.mark.parametrize(
    "evidence_type",
    [
        None,
        123,
        True,
        [],
        {},
    ],
)
def test_non_string_evidence_type(
    agent,
    evidence_type,
):

    result = agent.analyze(
        evidence="Test evidence",
        evidence_type=evidence_type,
    )

    assert result["success"] is False

    assert result["error"]["code"] == "invalid_input"


# =========================================================
# EXTRACTOR FAILURE TESTS
# =========================================================

def test_extractor_failure():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            exception=RuntimeError("Extractor unavailable")
        )
    )

    result = agent.analyze("Test evidence")

    assert result["success"] is False

    assert result["error"]["code"] == "analysis_failed"


def test_extractor_invalid_response():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response=None
        )
    )

    result = agent.analyze("Test evidence")

    assert result["success"] is False

    assert result["error"]["code"] == "analysis_failed"


@pytest.mark.parametrize(
    "response",
    [
        [],
        "invalid",
        123,
        True,
    ],
)
def test_extractor_non_dictionary_response(response):

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response=response
        )
    )

    result = agent.analyze("Test evidence")

    assert result["success"] is False

    assert result["error"]["code"] == "analysis_failed"


def test_extractor_reports_failure():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": False,
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["success"] is False

    assert result["error"]["code"] == "analysis_failed"


def test_extractor_empty_success_response():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["success"] is True

    assert result["summary"]["total_indicators"] == 0


# =========================================================
# VERIFICATION AND PRIVACY TESTS
# =========================================================

def test_verification_status_unverified(agent):

    result = agent.analyze("Test evidence")

    assert result["verification"]["status"] == "UNVERIFIED"


def test_external_lookup_not_performed(agent):

    result = agent.analyze("Test evidence")

    assert result["verification"][
        "external_lookup_performed"
    ] is False


def test_external_services_not_contacted(agent):

    result = agent.analyze("Test evidence")

    assert result["metadata"][
        "external_services_contacted"
    ] is False


def test_verification_message_present(agent):

    result = agent.analyze("Test evidence")

    assert result["verification"]["message"]


def test_agent_does_not_claim_malicious_status(agent):

    result = agent.analyze("Test evidence")

    message = result["verification"]["message"].lower()

    assert "not been independently verified" in message


def test_error_response_remains_unverified(agent):

    result = agent.analyze(
        evidence="",
    )

    assert result["verification"]["status"] == "UNVERIFIED"

    assert result["verification"][
        "external_lookup_performed"
    ] is False


# =========================================================
# METADATA TESTS
# =========================================================

def test_analysis_method(agent):

    result = agent.analyze("Test evidence")

    assert result["metadata"]["analysis_method"] == (
        "rule_based_extraction"
    )


def test_analysis_started_timestamp(agent):

    result = agent.analyze("Test evidence")

    assert result["metadata"]["analysis_started_at"]


def test_completed_timestamp(agent):

    result = agent.analyze("Test evidence")

    assert result["metadata"]["completed_at"]


def test_duration_is_numeric(agent):

    result = agent.analyze("Test evidence")

    assert isinstance(
        result["metadata"]["duration_ms"],
        (int, float),
    )


def test_duration_is_non_negative(agent):

    result = agent.analyze("Test evidence")

    assert result["metadata"]["duration_ms"] >= 0


def test_indicators_reused_false_for_fresh_extraction(agent):

    result = agent.analyze("Test evidence")

    assert result["metadata"]["indicators_reused"] is False


def test_indicators_reused_true_for_existing_data():

    agent = IntelligenceAgent()

    result = agent.analyze(
        evidence="Test evidence",
        existing_indicators={},
    )

    assert result["metadata"]["indicators_reused"] is True


# =========================================================
# ERROR RESPONSE TESTS
# =========================================================

def test_error_response_structure(agent):

    result = agent.analyze("")

    assert result["success"] is False

    assert result["agent"]["status"] == "failed"

    assert result["analysis_id"]

    assert "error" in result

    assert "verification" in result

    assert "metadata" in result


def test_error_response_agent_name(agent):

    result = agent.analyze("")

    assert result["agent"]["name"] == "IntelligenceAgent"


def test_error_response_version(agent):

    result = agent.analyze("")

    assert result["agent"]["version"] == "1.1.0"


def test_invalid_input_error_code(agent):

    result = agent.analyze("")

    assert result["error"]["code"] == "invalid_input"


def test_error_message_is_string(agent):

    result = agent.analyze("")

    assert isinstance(
        result["error"]["message"],
        str,
    )


def test_analysis_failure_message_is_safe():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            exception=RuntimeError("Internal database details")
        )
    )

    result = agent.analyze("Test evidence")

    assert result["error"]["message"] == (
        "Intelligence analysis could not be completed."
    )

    assert "Internal database details" not in (
        result["error"]["message"]
    )


# =========================================================
# PUBLIC FUNCTION TESTS
# =========================================================

def test_public_function(monkeypatch, extractor):

    import agents.intelligence_agent as intelligence_module

    test_agent = IntelligenceAgent(
        extractor=extractor
    )

    monkeypatch.setattr(
        intelligence_module,
        "intelligence_agent",
        test_agent,
    )

    result = run_intelligence_analysis(
        evidence="Suspicious message"
    )

    assert result["success"] is True


def test_public_function_with_existing_indicators(
    monkeypatch,
):

    import agents.intelligence_agent as intelligence_module

    test_agent = IntelligenceAgent()

    monkeypatch.setattr(
        intelligence_module,
        "intelligence_agent",
        test_agent,
    )

    result = run_intelligence_analysis(
        evidence="Suspicious message",
        existing_indicators={
            "urls": [
                "https://example.com",
            ],
        },
    )

    assert result["success"] is True

    assert result["metadata"]["indicators_reused"] is True


# =========================================================
# MULTIPLE INDICATOR TESTS
# =========================================================

def test_multiple_indicators():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "indicators": {
                    "urls": [
                        "https://one.example",
                        "https://two.example",
                    ],
                    "phone_numbers": [
                        "9876543210",
                        "9123456780",
                    ],
                    "emails": [
                        "one@example.com",
                        "two@example.com",
                    ],
                    "upi_ids": [
                        "one@okaxis",
                        "two@oksbi",
                    ],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    counts = result["indicator_counts"]

    assert counts["urls"] == 2

    assert counts["phone_numbers"] == 2

    assert counts["emails"] == 2

    assert counts["upi_ids"] == 2


def test_multiple_keyword_categories_counted():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "suspicious_keywords": {
                    "urgency": [
                        "urgent",
                        "immediately",
                    ],
                    "financial": [
                        "payment",
                    ],
                },
            }
        )
    )

    result = agent.analyze("Test evidence")

    assert result["indicator_counts"][
        "suspicious_keywords"
    ] == 3


def test_all_indicators_empty():

    agent = IntelligenceAgent(
        extractor=FakeExtractor(
            response={
                "success": True,
                "indicators": {
                    "urls": [],
                    "phone_numbers": [],
                    "emails": [],
                    "upi_ids": [],
                    "suspicious_keywords": {},
                },
            }
        )
    )

    result = agent.analyze("Normal message")

    assert result["success"] is True

    assert result["summary"]["total_indicators"] == 0


# =========================================================
# FINAL INTEGRITY TESTS
# =========================================================

def test_result_contains_all_expected_indicator_fields(agent):

    result = agent.analyze("Test evidence")

    expected = {
        "urls",
        "phone_numbers",
        "emails",
        "upi_ids",
        "suspicious_keywords",
    }

    assert set(
        result["intelligence"].keys()
    ) == expected


def test_indicator_counts_are_non_negative(agent):

    result = agent.analyze("Test evidence")

    for count in result["indicator_counts"].values():

        assert count >= 0


def test_success_status_completed(agent):

    result = agent.analyze("Test evidence")

    assert result["success"] is True

    assert result["agent"]["status"] == "completed"


def test_each_analysis_gets_unique_id(agent):

    first = agent.analyze("First evidence")

    second = agent.analyze("Second evidence")

    assert first["analysis_id"] != second["analysis_id"]


def test_analysis_does_not_mutate_existing_indicators():

    existing = {
        "urls": [
            "https://example.com",
            "https://example.com",
        ],
    }

    original = {
        "urls": list(existing["urls"]),
    }

    agent = IntelligenceAgent()

    agent.analyze(
        evidence="Test evidence",
        existing_indicators=existing,
    )

    assert existing == original


def test_analysis_result_has_boolean_success(agent):

    result = agent.analyze("Test evidence")

    assert isinstance(result["success"], bool)


def test_failed_analysis_has_boolean_success(agent):

    result = agent.analyze("")

    assert result["success"] is False


# =========================================================
# TEST SUMMARY
# =========================================================

if __name__ == "__main__":

    print("\n" + "=" * 65)

    print("SCAMSHIELD AI - INTELLIGENCE AGENT TEST SUITE")

    print("=" * 65)

    print("\nRun this test suite using pytest.")

    print("\nCommand:")

    print("python -m pytest tests/test_intelligence_agent.py -v")

    print("\n" + "=" * 65)