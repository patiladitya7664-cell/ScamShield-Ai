"""
=========================================================
SCAMSHIELD AI - EVIDENCE EXTRACTOR TEST SUITE
=========================================================

Coverage:
    1. URL extraction
    2. Email extraction
    3. Indian phone number extraction
    4. UPI ID extraction
    5. Duplicate removal
    6. Suspicious keyword detection
    7. Negation and false-positive handling
    8. Input validation
    9. Response contract
    10. Privacy and verification disclaimers

=========================================================
"""

import pytest

from extraction.evidence_extractor import (
    EvidenceExtractor,
    extract_evidence,
)


# =========================================================
# INITIALIZATION
# =========================================================

def test_extractor_initialization():
    extractor = EvidenceExtractor()
    assert isinstance(extractor, EvidenceExtractor)


def test_maximum_evidence_length():
    assert EvidenceExtractor.MAX_EVIDENCE_LENGTH == 20000


# =========================================================
# URL EXTRACTION
# =========================================================

def test_extract_http_url():
    result = EvidenceExtractor.extract_urls(
        "Visit http://example.com"
    )

    assert result == ["http://example.com"]


def test_extract_https_url():
    result = EvidenceExtractor.extract_urls(
        "Visit https://example.com"
    )

    assert result == ["https://example.com"]


def test_extract_www_url():
    result = EvidenceExtractor.extract_urls(
        "Visit www.example.com"
    )

    assert result == ["www.example.com"]


def test_extract_multiple_urls():
    result = EvidenceExtractor.extract_urls(
        "https://example.com and http://test.com"
    )

    assert len(result) == 2


def test_url_trailing_punctuation_removed():
    result = EvidenceExtractor.extract_urls(
        "Visit https://example.com."
    )

    assert result == ["https://example.com"]


def test_url_duplicate_removal():
    result = EvidenceExtractor.extract_urls(
        "https://example.com https://example.com"
    )

    assert len(result) == 1


def test_url_case_insensitive_duplicate_removal():
    result = EvidenceExtractor.extract_urls(
        "https://Example.com https://example.com"
    )

    assert len(result) == 1


def test_url_order_preserved():
    result = EvidenceExtractor.extract_urls(
        "https://first.com https://second.com"
    )

    assert result == [
        "https://first.com",
        "https://second.com",
    ]


def test_no_url_found():
    result = EvidenceExtractor.extract_urls(
        "This message contains no URL."
    )

    assert result == []


# =========================================================
# EMAIL EXTRACTION
# =========================================================

def test_extract_email():
    result = EvidenceExtractor.extract_emails(
        "Contact support@example.com"
    )

    assert result == ["support@example.com"]


def test_extract_multiple_emails():
    result = EvidenceExtractor.extract_emails(
        "a@example.com b@test.org"
    )

    assert len(result) == 2


def test_email_case_insensitive_duplicates():
    result = EvidenceExtractor.extract_emails(
        "User@example.com user@example.com"
    )

    assert len(result) == 1


def test_email_order_preserved():
    result = EvidenceExtractor.extract_emails(
        "first@example.com second@example.com"
    )

    assert result == [
        "first@example.com",
        "second@example.com",
    ]


def test_no_email_found():
    result = EvidenceExtractor.extract_emails(
        "No email address here."
    )

    assert result == []


# =========================================================
# PHONE NUMBER EXTRACTION
# =========================================================

@pytest.mark.parametrize(
    "phone",
    [
        "9876543210",
        "+919876543210",
        "919876543210",
        "+91 9876543210",
        "98765-43210",
    ],
)
def test_extract_indian_phone_numbers(phone):
    result = EvidenceExtractor.extract_phone_numbers(
        f"Call me at {phone}"
    )

    assert len(result) == 1


def test_extract_multiple_phone_numbers():
    result = EvidenceExtractor.extract_phone_numbers(
        "Call 9876543210 or 8765432109"
    )

    assert len(result) == 2


def test_phone_duplicate_removal():
    result = EvidenceExtractor.extract_phone_numbers(
        "9876543210 9876543210"
    )

    assert len(result) == 1


def test_phone_case_independent_behavior():
    result = EvidenceExtractor.extract_phone_numbers(
        "9876543210 9876543210"
    )

    assert result == ["9876543210"]


def test_invalid_phone_prefix_not_extracted():
    result = EvidenceExtractor.extract_phone_numbers(
        "1234567890"
    )

    assert result == []


def test_phone_embedded_in_word_not_extracted():
    result = EvidenceExtractor.extract_phone_numbers(
        "abc9876543210xyz"
    )

    assert result == []


def test_no_phone_found():
    result = EvidenceExtractor.extract_phone_numbers(
        "No phone number available."
    )

    assert result == []


# =========================================================
# UPI ID EXTRACTION
# =========================================================

def test_extract_upi_id():
    result = EvidenceExtractor.extract_upi_ids(
        "Send money to user@okaxis"
    )

    assert result == ["user@okaxis"]


def test_extract_multiple_upi_ids():
    result = EvidenceExtractor.extract_upi_ids(
        "user@okaxis and shop@ybl"
    )

    assert len(result) == 2


def test_upi_duplicate_removal():
    result = EvidenceExtractor.extract_upi_ids(
        "user@okaxis user@okaxis"
    )

    assert len(result) == 1


def test_email_not_returned_as_upi():
    result = EvidenceExtractor.extract_upi_ids(
        "Contact user@gmail.com"
    )

    assert result == []


def test_upi_and_email_separation():
    result = EvidenceExtractor.extract_upi_ids(
        "user@okaxis user@gmail.com"
    )

    assert "user@okaxis" in result
    assert "user@gmail.com" not in result


def test_no_upi_found():
    result = EvidenceExtractor.extract_upi_ids(
        "No UPI ID available."
    )

    assert result == []


# =========================================================
# SUSPICIOUS KEYWORD DETECTION
# =========================================================

@pytest.mark.parametrize(
    "text,category,keyword",
    [
        (
            "Please pay immediately",
            "urgent_payment",
            "pay immediately",
        ),
        (
            "Please share OTP",
            "otp_request",
            "share otp",
        ),
        (
            "There is an arrest warrant",
            "threats",
            "arrest warrant",
        ),
        (
            "Guaranteed returns available",
            "investment_scam",
            "guaranteed returns",
        ),
        (
            "Install AnyDesk now",
            "remote_access",
            "install anydesk",
        ),
        (
            "You have won a prize",
            "prize_scam",
            "you have won",
        ),
    ],
)
def test_suspicious_keyword_detection(
    text,
    category,
    keyword,
):
    result = EvidenceExtractor.extract_keywords(text)

    assert category in result
    assert keyword in result[category]


def test_multiple_keyword_categories():
    result = EvidenceExtractor.extract_keywords(
        "Share OTP and pay immediately"
    )

    assert "otp_request" in result
    assert "urgent_payment" in result


def test_keyword_detection_case_insensitive():
    result = EvidenceExtractor.extract_keywords(
        "PLEASE SHARE OTP"
    )

    assert "otp_request" in result


def test_keyword_duplicate_not_repeated():
    result = EvidenceExtractor.extract_keywords(
        "Please share OTP. Please share OTP."
    )

    assert result["otp_request"].count("share otp") == 1


def test_no_keyword_found():
    result = EvidenceExtractor.extract_keywords(
        "Hello, how are you?"
    )

    assert result == {}


def test_negated_otp_warning_not_detected_as_request():
    result = EvidenceExtractor.extract_keywords(
        "Do not share OTP with anyone."
    )

    assert "otp_request" not in result


def test_negated_payment_warning_not_detected_as_request():
    result = EvidenceExtractor.extract_keywords(
        "Do not pay immediately without verification."
    )

    assert "urgent_payment" not in result


# =========================================================
# COMPLETE EXTRACTION
# =========================================================

def test_normal_extraction():
    result = EvidenceExtractor.extract(
        "Visit https://example.com or contact support@example.com"
    )

    assert result["success"] is True
    assert "urls" in result["indicators"]
    assert "emails" in result["indicators"]


def test_all_indicator_types_extracted():
    evidence = (
        "Visit https://example.com "
        "Contact user@gmail.com "
        "Call 9876543210 "
        "UPI user@okaxis"
    )

    result = EvidenceExtractor.extract(evidence)

    indicators = result["indicators"]

    assert len(indicators["urls"]) == 1
    assert len(indicators["emails"]) == 1
    assert len(indicators["phone_numbers"]) == 1
    assert len(indicators["upi_ids"]) == 1


def test_empty_indicator_response():
    result = EvidenceExtractor.extract(
        "Hello, this is a normal message."
    )

    assert result["indicator_count"] == 0


def test_indicator_count_accuracy():
    result = EvidenceExtractor.extract(
        "https://example.com user@gmail.com "
        "9876543210 user@okaxis"
    )

    assert result["indicator_count"] == 4


def test_keyword_categories_detected():
    result = EvidenceExtractor.extract(
        "Please share OTP"
    )

    assert "otp_request" in result[
        "keyword_categories_detected"
    ]


# =========================================================
# INPUT VALIDATION
# =========================================================

@pytest.mark.parametrize(
    "evidence",
    [
        "",
        " ",
        "\n",
        "\t",
    ],
)
def test_empty_evidence_rejected(evidence):
    with pytest.raises(ValueError):
        EvidenceExtractor.extract(evidence)


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
def test_non_string_evidence_rejected(evidence):
    with pytest.raises(TypeError):
        EvidenceExtractor.extract(evidence)


def test_evidence_exceeding_maximum_length():
    evidence = "A" * 20001

    with pytest.raises(ValueError):
        EvidenceExtractor.extract(evidence)


def test_maximum_allowed_evidence_length():
    evidence = "A" * 20000

    result = EvidenceExtractor.extract(evidence)

    assert result["success"] is True


def test_whitespace_is_trimmed():
    result = EvidenceExtractor.extract(
        "   https://example.com   "
    )

    assert result["evidence_length"] == len(
        "https://example.com"
    )


# =========================================================
# RESPONSE CONTRACT
# =========================================================

def test_response_contains_success():
    result = EvidenceExtractor.extract("Hello")

    assert result["success"] is True


def test_response_contains_indicators():
    result = EvidenceExtractor.extract("Hello")

    assert isinstance(result["indicators"], dict)


def test_response_contains_suspicious_keywords():
    result = EvidenceExtractor.extract("Hello")

    assert isinstance(
        result["suspicious_keywords"],
        dict,
    )


def test_response_contains_indicator_count():
    result = EvidenceExtractor.extract("Hello")

    assert isinstance(
        result["indicator_count"],
        int,
    )


def test_response_contains_evidence_length():
    result = EvidenceExtractor.extract("Hello")

    assert result["evidence_length"] == 5


def test_response_contains_verification_status():
    result = EvidenceExtractor.extract("Hello")

    assert result["verification_status"] == "UNVERIFIED"


def test_response_contains_disclaimer():
    result = EvidenceExtractor.extract("Hello")

    assert "unverified" in result["disclaimer"].lower()
    assert "fraud" in result["disclaimer"].lower()


def test_extraction_does_not_claim_external_verification():
    result = EvidenceExtractor.extract(
        "https://example.com"
    )

    assert result["verification_status"] == "UNVERIFIED"


# =========================================================
# PUBLIC FUNCTION
# =========================================================

def test_public_extract_function():
    result = extract_evidence(
        "Visit https://example.com"
    )

    assert result["success"] is True
    assert len(result["indicators"]["urls"]) == 1


def test_public_function_matches_class_method():
    evidence = "user@gmail.com"

    direct = EvidenceExtractor.extract(evidence)
    public = extract_evidence(evidence)

    assert direct == public


# =========================================================
# DETERMINISTIC BEHAVIOR
# =========================================================

def test_repeated_extraction_consistency():
    evidence = (
        "Visit https://example.com "
        "Contact user@gmail.com "
        "Share OTP"
    )

    first = EvidenceExtractor.extract(evidence)
    second = EvidenceExtractor.extract(evidence)

    assert first["indicators"] == second["indicators"]
    assert first["suspicious_keywords"] == (
        second["suspicious_keywords"]
    )
    assert first["indicator_count"] == (
        second["indicator_count"]
    )