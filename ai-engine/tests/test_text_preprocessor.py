"""
=========================================================
SCAMSHIELD AI - TEXT PREPROCESSOR REGRESSION TEST SUITE
=========================================================

Version: 1.0.0
Target: TextPreprocessor v2.0.0

Coverage:
    1. Initialization and version.
    2. Unicode normalization.
    3. Control character removal.
    4. URL extraction and cleaning.
    5. Email extraction.
    6. UPI ID extraction.
    7. Indian phone number extraction.
    8. Sensitive information masking.
    9. Currency normalization.
    10. PAN, Aadhaar and card masking.
    11. Text preprocessing.
    12. Evidence validation.
    13. Evidence type validation.
    14. Metadata generation.
    15. Privacy and data integrity.
    16. Deterministic behavior.
    17. Known limitation regression tests.

Run:
    pytest tests/test_text_preprocessor.py -v

=========================================================
"""

import pytest
import unicodedata

from utils.text_preprocessor import TextPreprocessor


# =========================================================
# 1. INITIALIZATION AND VERSION
# =========================================================

class TestInitialization:

    def test_preprocessor_initialization(self):

        assert TextPreprocessor is not None

    def test_version(self):

        assert TextPreprocessor.VERSION == "2.0.0"

    def test_max_evidence_length(self):

        assert TextPreprocessor.MAX_EVIDENCE_LENGTH == 20000

    def test_supported_evidence_types(self):

        expected = {
            "message",
            "url",
            "call",
            "transaction",
            "screenshot",
            "email"
        }

        assert (
            TextPreprocessor.SUPPORTED_EVIDENCE_TYPES
            == expected
        )


# =========================================================
# 2. UNICODE NORMALIZATION
# =========================================================

class TestUnicodeNormalization:

    def test_nfkc_normalization(self):

        text = "ＡＢＣ１２３"

        result = TextPreprocessor.normalize_unicode(text)

        assert result == "ABC123"

    def test_hindi_text_preservation(self):

        text = "आपका बैंक अकाउंट बंद हो जाएगा"

        result = TextPreprocessor.normalize_unicode(text)

        assert result == text

    def test_hinglish_text_preservation(self):

        text = "Aapka bank account block ho jayega"

        result = TextPreprocessor.normalize_unicode(text)

        assert result == text

    def test_unicode_compatibility_characters(self):

        text = "① ② ③"

        result = TextPreprocessor.normalize_unicode(text)

        assert result == "1 2 3"

    def test_unicode_normalization_consistency(self):

        first = "Ａｄｍｉｎ"

        second = "Admin"

        result_first = TextPreprocessor.normalize_unicode(first)

        result_second = TextPreprocessor.normalize_unicode(second)

        assert result_first == result_second


# =========================================================
# 3. CONTROL CHARACTER REMOVAL
# =========================================================

class TestControlCharacterRemoval:

    def test_remove_null_character(self):

        text = "Hello\x00World"

        result = TextPreprocessor.remove_control_characters(text)

        assert "\x00" not in result

    def test_preserve_newlines(self):

        text = "First line\nSecond line"

        result = TextPreprocessor.remove_control_characters(text)

        assert "\n" in result

    def test_preserve_tabs(self):

        text = "First\tSecond"

        result = TextPreprocessor.remove_control_characters(text)

        assert "\t" in result

    def test_remove_formatting_characters(self):

        text = "Hello\u200bWorld"

        result = TextPreprocessor.remove_control_characters(text)

        assert "\u200b" not in result

    def test_preserve_hindi_characters(self):

        text = "नमस्ते दुनिया"

        result = TextPreprocessor.remove_control_characters(text)

        assert result == text


# =========================================================
# 4. URL EXTRACTION
# =========================================================

class TestURLExtraction:

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com",
            "http://example.com",
            "https://example.com/login",
            "www.example.com",
            "https://example.com/path?id=123"
        ]
    )
    def test_extract_valid_url_patterns(self, url):

        result = TextPreprocessor.extract_urls(url)

        assert len(result) == 1
        assert result[0] == url

    def test_extract_multiple_urls(self):

        text = (
            "Visit https://example.com "
            "and https://google.com"
        )

        result = TextPreprocessor.extract_urls(text)

        assert len(result) == 2

    def test_remove_trailing_punctuation(self):

        text = "Visit https://example.com."

        result = TextPreprocessor.extract_urls(text)

        assert result == ["https://example.com"]

    def test_remove_unbalanced_parenthesis(self):

        text = "Visit https://example.com/path)."

        result = TextPreprocessor.extract_urls(text)

        assert result == ["https://example.com/path"]

    def test_preserve_balanced_parenthesis(self):

        text = "Visit https://example.com/path(test)"

        result = TextPreprocessor.extract_urls(text)

        assert result == [
            "https://example.com/path(test)"
        ]

    def test_remove_duplicate_urls(self):

        text = (
            "https://example.com "
            "https://example.com"
        )

        result = TextPreprocessor.extract_urls(text)

        assert len(result) == 1

    def test_case_insensitive_duplicate_removal(self):

        text = (
            "https://Example.com "
            "https://example.com"
        )

        result = TextPreprocessor.extract_urls(text)

        assert len(result) == 1

    def test_empty_url_input(self):

        assert TextPreprocessor.extract_urls("") == []

    def test_invalid_input(self):

        assert TextPreprocessor.extract_urls(None) == []


# =========================================================
# 5. EMAIL EXTRACTION
# =========================================================

class TestEmailExtraction:

    @pytest.mark.parametrize(
        "email",
        [
            "test@example.com",
            "support@company.in",
            "admin123@example.org",
            "user.name@example.com"
        ]
    )
    def test_extract_email(self, email):

        result = TextPreprocessor.extract_emails(email)

        assert len(result) == 1
        assert result[0] == email

    def test_extract_multiple_emails(self):

        text = (
            "Contact admin@example.com "
            "or support@example.org"
        )

        result = TextPreprocessor.extract_emails(text)

        assert len(result) == 2

    def test_remove_duplicate_emails(self):

        text = (
            "admin@example.com "
            "admin@example.com"
        )

        result = TextPreprocessor.extract_emails(text)

        assert len(result) == 1

    def test_case_insensitive_email_duplicates(self):

        text = (
            "Admin@example.com "
            "admin@example.com"
        )

        result = TextPreprocessor.extract_emails(text)

        assert len(result) == 1

    def test_empty_email_input(self):

        assert TextPreprocessor.extract_emails("") == []

    def test_invalid_email_input(self):

        assert TextPreprocessor.extract_emails(None) == []


# =========================================================
# 6. UPI ID EXTRACTION
# =========================================================

class TestUPIExtraction:

    @pytest.mark.parametrize(
        "upi",
        [
            "9876543210@upi",
            "aditya@okaxis",
            "user@paytm",
            "merchant@oksbi"
        ]
    )
    def test_extract_possible_upi_id(self, upi):

        result = TextPreprocessor.extract_upi_ids(upi)

        assert len(result) == 1
        assert result[0].lower() == upi.lower()

    def test_extract_multiple_upi_ids(self):

        text = (
            "Pay to aditya@okaxis "
            "or merchant@paytm"
        )

        result = TextPreprocessor.extract_upi_ids(text)

        assert len(result) == 2

    def test_exclude_email_addresses(self):

        text = "Contact admin@example.com"

        result = TextPreprocessor.extract_upi_ids(text)

        assert result == []

    def test_exclude_url_overlapping_matches(self):

        text = "https://example.com"

        result = TextPreprocessor.extract_upi_ids(text)

        assert result == []

    def test_remove_duplicate_upi_ids(self):

        text = (
            "aditya@okaxis "
            "aditya@okaxis"
        )

        result = TextPreprocessor.extract_upi_ids(text)

        assert len(result) == 1

    def test_empty_upi_input(self):

        assert TextPreprocessor.extract_upi_ids("") == []

    def test_invalid_upi_input(self):

        assert TextPreprocessor.extract_upi_ids(None) == []


# =========================================================
# 7. PHONE NUMBER EXTRACTION
# =========================================================

class TestPhoneExtraction:

    @pytest.mark.parametrize(
        "phone",
        [
            "9876543210",
            "+919876543210",
            "919876543210",
            "+91 98765 43210",
            "98765-43210"
        ]
    )
    def test_extract_indian_phone_number(self, phone):

        result = TextPreprocessor.extract_phone_numbers(phone)

        assert len(result) == 1

    def test_extract_multiple_phone_numbers(self):

        text = (
            "Call 9876543210 "
            "or 9123456789"
        )

        result = TextPreprocessor.extract_phone_numbers(text)

        assert len(result) == 2

    def test_remove_duplicate_phone_numbers(self):

        text = (
            "9876543210 "
            "9876543210"
        )

        result = TextPreprocessor.extract_phone_numbers(text)

        assert len(result) == 1

    def test_preserve_original_phone_format(self):

        phone = "+91 98765 43210"

        result = TextPreprocessor.extract_phone_numbers(phone)

        assert result[0] == phone

    def test_empty_phone_input(self):

        assert TextPreprocessor.extract_phone_numbers("") == []

    def test_invalid_phone_input(self):

        assert TextPreprocessor.extract_phone_numbers(None) == []


# =========================================================
# 8. URL MASKING
# =========================================================

class TestURLMasking:

    def test_mask_https_url(self):

        text = "Visit https://example.com"

        result = TextPreprocessor.mask_sensitive_information(text)

        assert "https://example.com" not in result
        assert "URL_TOKEN" in result

    def test_mask_multiple_urls(self):

        text = (
            "https://example.com "
            "https://google.com"
        )

        result = TextPreprocessor.mask_sensitive_information(text)

        assert result.count("URL_TOKEN") == 2

    def test_preserve_non_url_text(self):

        text = "Your account is blocked"

        result = TextPreprocessor.mask_sensitive_information(text)

        assert "account" in result
        assert "blocked" in result


# =========================================================
# 9. EMAIL MASKING
# =========================================================

class TestEmailMasking:

    def test_mask_email(self):

        text = "Contact admin@example.com"

        result = TextPreprocessor.mask_sensitive_information(text)

        assert "admin@example.com" not in result
        assert "EMAIL_TOKEN" in result


# =========================================================
# 10. UPI MASKING
# =========================================================

class TestUPIMasking:

    def test_mask_upi_id(self):

        text = "Pay aditya@okaxis"

        result = TextPreprocessor.mask_sensitive_information(text)

        assert "aditya@okaxis" not in result
        assert "UPI_TOKEN" in result

    def test_email_not_classified_as_upi(self):

        text = "admin@example.com"

        result = TextPreprocessor.mask_sensitive_information(text)

        assert "EMAIL_TOKEN" in result
        assert "UPI_TOKEN" not in result


# =========================================================
# 11. PHONE MASKING
# =========================================================

class TestPhoneMasking:

    def test_mask_phone_number(self):

        text = "Call 9876543210"

        result = TextPreprocessor.mask_sensitive_information(text)

        assert "9876543210" not in result
        assert "PHONE_TOKEN" in result

    def test_mask_country_code_phone(self):

        text = "Call +919876543210"

        result = TextPreprocessor.mask_sensitive_information(text)

        assert "+919876543210" not in result
        assert "PHONE_TOKEN" in result


# =========================================================
# 12. PAN MASKING
# =========================================================

class TestPANMasking:

    def test_mask_pan_number(self):

        text = "PAN ABCDE1234F"

        result = TextPreprocessor.mask_sensitive_information(text)

        assert "ABCDE1234F" not in result
        assert "PAN_TOKEN" in result


# =========================================================
# 13. AADHAAR MASKING
# =========================================================

class TestAadhaarMasking:

    def test_mask_aadhaar_number(self):

        text = "Aadhaar 1234 5678 9012"

        result = TextPreprocessor.mask_sensitive_information(text)

        assert "1234 5678 9012" not in result
        assert "AADHAAR_TOKEN" in result

    def test_mask_continuous_aadhaar(self):

        text = "123456789012"

        result = TextPreprocessor.mask_sensitive_information(text)

        assert "123456789012" not in result
        assert "AADHAAR_TOKEN" in result


# =========================================================
# 14. CARD MASKING
# =========================================================

class TestCardMasking:

    def test_mask_card_number(self):

        text = "4111111111111111"

        result = TextPreprocessor.mask_sensitive_information(text)

        assert "4111111111111111" not in result
        assert "CARD_TOKEN" in result

    def test_mask_formatted_card_number(self):

        text = "4111 1111 1111 1111"

        result = TextPreprocessor.mask_sensitive_information(text)

        assert "4111 1111 1111 1111" not in result
        assert "CARD_TOKEN" in result


# =========================================================
# 15. CURRENCY NORMALIZATION
# =========================================================

class TestCurrencyNormalization:

    @pytest.mark.parametrize(
        "text",
        [
            "Pay ₹500",
            "Pay Rs. 500",
            "Pay INR 1000",
            "Pay rs 250"
        ]
    )
    def test_mask_currency_values(self, text):

        result = TextPreprocessor.preprocess(text)

        assert "CURRENCY_TOKEN" in result

    def test_currency_without_sensitive_masking(self):

        text = "Pay ₹500"

        result = TextPreprocessor.preprocess(
            text,
            mask_sensitive=False
        )

        assert "500" not in result
        assert "NUMBER_TOKEN" in result


# =========================================================
# 16. TEXT NORMALIZATION
# =========================================================

class TestTextNormalization:

    def test_lowercase_normalization(self):

        result = TextPreprocessor.normalize_text(
            "HELLO WORLD"
        )

        assert result == "hello world"

    def test_whitespace_normalization(self):

        result = TextPreprocessor.normalize_text(
            "Hello     World"
        )

        assert result == "hello world"

    def test_leading_trailing_whitespace(self):

        result = TextPreprocessor.normalize_text(
            "   Hello World   "
        )

        assert result == "hello world"

    def test_hindi_text_normalization(self):

        text = "आपका बैंक अकाउंट बंद होगा"

        result = TextPreprocessor.normalize_text(text)

        assert "बैंक" in result

    def test_hinglish_text_normalization(self):

        text = "Aapka Account Block Ho Jayega"

        result = TextPreprocessor.normalize_text(text)

        assert result == "aapka account block ho jayega"


# =========================================================
# 17. MAIN PREPROCESSING
# =========================================================

class TestPreprocessing:

    def test_basic_preprocessing(self):

        result = TextPreprocessor.preprocess(
            "HELLO WORLD"
        )

        assert result == "hello world"

    def test_number_normalization(self):

        result = TextPreprocessor.preprocess(
            "Your OTP is 123456"
        )

        assert "123456" not in result
        assert "NUMBER_TOKEN" in result

    def test_sensitive_masking_enabled(self):

        result = TextPreprocessor.preprocess(
            "Call 9876543210"
        )

        assert "9876543210" not in result

    def test_sensitive_masking_disabled(self):

        result = TextPreprocessor.preprocess(
            "Call 9876543210",
            mask_sensitive=False
        )

        # Standalone numbers are still normalized.
        assert "9876543210" not in result
        assert "NUMBER_TOKEN" in result

    def test_invalid_mask_sensitive_argument(self):

        with pytest.raises(TypeError):

            TextPreprocessor.preprocess(
                "Hello",
                mask_sensitive="yes"
            )

    def test_preserve_fraud_context(self):

        text = (
            "Your bank account will be blocked "
            "if you do not verify immediately."
        )

        result = TextPreprocessor.preprocess(text)

        assert "bank account" in result
        assert "blocked" in result
        assert "verify" in result

    def test_hinglish_fraud_context(self):

        text = (
            "Aapka bank account block ho jayega. "
            "Abhi OTP share karo."
        )

        result = TextPreprocessor.preprocess(text)

        assert "bank account" in result
        assert "block" in result
        assert "otp" in result
        assert "share" in result


# =========================================================
# 18. INPUT VALIDATION
# =========================================================

class TestInputValidation:

    @pytest.mark.parametrize(
        "value",
        [
            None,
            123,
            12.5,
            [],
            {},
            True
        ]
    )
    def test_reject_non_string_input(self, value):

        with pytest.raises(TypeError):

            TextPreprocessor.preprocess(value)

    @pytest.mark.parametrize(
        "value",
        [
            "",
            " ",
            "\n",
            "\t"
        ]
    )
    def test_reject_empty_input(self, value):

        with pytest.raises(ValueError):

            TextPreprocessor.preprocess(value)

    def test_accept_maximum_length_input(self):

        text = "a" * 20000

        result = TextPreprocessor.preprocess(text)

        assert isinstance(result, str)

    def test_reject_oversized_input(self):

        text = "a" * 20001

        with pytest.raises(ValueError):

            TextPreprocessor.preprocess(text)


# =========================================================
# 19. EVIDENCE TYPE VALIDATION
# =========================================================

class TestEvidenceTypeValidation:

    @pytest.mark.parametrize(
        "evidence_type",
        [
            "message",
            "url",
            "call",
            "transaction",
            "screenshot",
            "email"
        ]
    )
    def test_supported_evidence_types(self, evidence_type):

        result = TextPreprocessor.process_evidence(
            "Suspicious evidence",
            evidence_type
        )

        assert result["success"] is True
        assert result["evidence_type"] == evidence_type

    def test_case_insensitive_evidence_type(self):

        result = TextPreprocessor.process_evidence(
            "Suspicious evidence",
            "MESSAGE"
        )

        assert result["evidence_type"] == "message"

    def test_whitespace_evidence_type(self):

        result = TextPreprocessor.process_evidence(
            "Suspicious evidence",
            " message "
        )

        assert result["evidence_type"] == "message"

    def test_reject_unsupported_evidence_type(self):

        with pytest.raises(ValueError):

            TextPreprocessor.process_evidence(
                "Suspicious evidence",
                "audio"
            )

    def test_reject_non_string_evidence_type(self):

        with pytest.raises(TypeError):

            TextPreprocessor.process_evidence(
                "Suspicious evidence",
                123
            )

    def test_optional_evidence_type(self):

        result = TextPreprocessor.process_evidence(
            "Suspicious evidence"
        )

        assert result["evidence_type"] is None


# =========================================================
# 20. COMPLETE EVIDENCE PROCESSING
# =========================================================

class TestProcessEvidence:

    def test_success_response(self):

        result = TextPreprocessor.process_evidence(
            "Suspicious bank message",
            "message"
        )

        assert result["success"] is True

    def test_version_in_response(self):

        result = TextPreprocessor.process_evidence(
            "Suspicious message"
        )

        assert result["version"] == "2.0.0"

    def test_processed_text_in_response(self):

        result = TextPreprocessor.process_evidence(
            "HELLO WORLD"
        )

        assert "processed_text" in result
        assert result["processed_text"] == "hello world"

    def test_indicators_structure(self):

        result = TextPreprocessor.process_evidence(
            "Visit https://example.com "
            "or contact admin@example.com"
        )

        expected_keys = {
            "urls",
            "emails",
            "upi_ids",
            "phone_numbers"
        }

        assert set(result["indicators"].keys()) == expected_keys

    def test_indicator_count(self):

        result = TextPreprocessor.process_evidence(
            "Visit https://example.com "
            "and contact admin@example.com"
        )

        assert result["indicator_count"] == 2

    def test_character_count(self):

        text = "Suspicious evidence"

        result = TextPreprocessor.process_evidence(text)

        assert result["character_count"] == len(text)

    def test_processed_character_count(self):

        result = TextPreprocessor.process_evidence(
            "HELLO WORLD"
        )

        assert (
            result["processed_character_count"]
            == len(result["processed_text"])
        )

    def test_verification_status(self):

        result = TextPreprocessor.process_evidence(
            "Suspicious evidence"
        )

        assert result["verification_status"] == "UNVERIFIED"

    def test_disclaimer_exists(self):

        result = TextPreprocessor.process_evidence(
            "Suspicious evidence"
        )

        assert isinstance(result["disclaimer"], str)
        assert "unverified" in result["disclaimer"].lower()

    def test_all_required_metadata_fields(self):

        result = TextPreprocessor.process_evidence(
            "Suspicious evidence",
            "message"
        )

        required_fields = {
            "success",
            "version",
            "evidence_type",
            "processed_text",
            "indicators",
            "indicator_count",
            "character_count",
            "processed_character_count",
            "verification_status",
            "disclaimer"
        }

        assert required_fields.issubset(result.keys())


# =========================================================
# 21. PRIVACY AND DATA INTEGRITY
# =========================================================

class TestPrivacyAndDataIntegrity:

    def test_original_evidence_unchanged(self):

        original = "Call 9876543210 immediately"

        snapshot = original

        TextPreprocessor.process_evidence(original)

        assert original == snapshot

    def test_phone_not_exposed_in_processed_text(self):

        result = TextPreprocessor.process_evidence(
            "Call 9876543210"
        )

        assert "9876543210" not in result["processed_text"]

    def test_email_not_exposed_in_processed_text(self):

        result = TextPreprocessor.process_evidence(
            "Contact admin@example.com"
        )

        assert "admin@example.com" not in result["processed_text"]

    def test_url_not_exposed_in_processed_text(self):

        result = TextPreprocessor.process_evidence(
            "Visit https://example.com"
        )

        assert "https://example.com" not in result["processed_text"]

    def test_upi_not_exposed_in_processed_text(self):

        result = TextPreprocessor.process_evidence(
            "Pay aditya@okaxis"
        )

        assert "aditya@okaxis" not in result["processed_text"]

    def test_indicators_remain_separate_from_processed_text(self):

        result = TextPreprocessor.process_evidence(
            "Call 9876543210"
        )

        assert "PHONE_TOKEN" in result["processed_text"]

        assert (
            "9876543210"
            in result["indicators"]["phone_numbers"]
        )


# =========================================================
# 22. DETERMINISTIC BEHAVIOR
# =========================================================

class TestDeterministicBehavior:

    def test_repeated_preprocessing(self):

        text = "Your account is blocked. Call 9876543210"

        first = TextPreprocessor.preprocess(text)

        second = TextPreprocessor.preprocess(text)

        assert first == second

    def test_repeated_indicator_extraction(self):

        text = (
            "Visit https://example.com "
            "and call 9876543210"
        )

        first = TextPreprocessor.process_evidence(text)

        second = TextPreprocessor.process_evidence(text)

        assert first["indicators"] == second["indicators"]

    def test_repeated_metadata_consistency(self):

        text = "Suspicious bank message"

        first = TextPreprocessor.process_evidence(text)

        second = TextPreprocessor.process_evidence(text)

        assert first["processed_text"] == second["processed_text"]

        assert first["indicator_count"] == second["indicator_count"]


# =========================================================
# 23. KNOWN LIMITATION REGRESSION TESTS
# =========================================================

class TestKnownLimitations:

    @pytest.mark.xfail(
        strict=False,
        reason=(
            "Unicode-normalized indicator extraction "
            "is a pending improvement."
        )
    )
    def test_extract_full_width_phone_number(self):

        text = "９８７６５４３２１０"

        result = TextPreprocessor.extract_phone_numbers(text)

        assert len(result) == 1

    @pytest.mark.xfail(
        strict=False,
        reason=(
            "Currency-versus-phone precedence "
            "requires targeted improvement."
        )
    )
    def test_currency_amount_not_classified_as_phone(self):

        text = "₹9876543210"

        result = TextPreprocessor.extract_phone_numbers(text)

        assert result == []

    @pytest.mark.xfail(
        strict=False,
        reason=(
            "Bare-domain extraction is not supported "
            "by the current URL pattern."
        )
    )
    def test_extract_bare_domain(self):

        text = "Visit example.com"

        result = TextPreprocessor.extract_urls(text)

        assert result == ["example.com"]

    @pytest.mark.xfail(
        strict=False,
        reason=(
            "Card pattern currently may mask "
            "unrelated long numeric identifiers."
        )
    )
    def test_preserve_long_transaction_identifier(self):

        text = "Transaction ID 1234567890123456"

        result = TextPreprocessor.mask_sensitive_information(text)

        assert "1234567890123456" in result

    @pytest.mark.xfail(
        strict=False,
        reason=(
            "Extraction methods currently need "
            "independent Unicode normalization."
        )
    )
    def test_normalize_unicode_before_extraction(self):

        text = "９８７６５４３２１０"

        normalized = TextPreprocessor.normalize_unicode(text)

        result = TextPreprocessor.extract_phone_numbers(normalized)

        assert len(result) == 1


# =========================================================
# 24. PUBLIC FUNCTION COMPATIBILITY
# =========================================================

class TestPublicFunctionCompatibility:

    def test_module_level_function_exists(self):

        from utils.text_preprocessor import preprocess_text

        assert callable(preprocess_text)

    def test_module_level_function_output(self):

        from utils.text_preprocessor import preprocess_text

        result = preprocess_text("HELLO WORLD")

        assert result == "hello world"

    def test_module_level_function_masks_sensitive_data(self):

        from utils.text_preprocessor import preprocess_text

        result = preprocess_text("Call 9876543210")

        assert "9876543210" not in result


# =========================================================
# 25. INTEGRATION CONTRACT
# =========================================================

class TestIntegrationContract:

    def test_detector_compatible_output(self):

        result = TextPreprocessor.process_evidence(
            "Your account will be blocked. "
            "Visit https://example.com",
            "message"
        )

        assert isinstance(result, dict)

        assert result["success"] is True

        assert isinstance(result["processed_text"], str)

        assert isinstance(result["indicators"], dict)

        assert isinstance(result["indicator_count"], int)

    def test_indicator_collections_are_lists(self):

        result = TextPreprocessor.process_evidence(
            "Visit https://example.com"
        )

        for value in result["indicators"].values():

            assert isinstance(value, list)

    def test_processed_text_contains_no_raw_url(self):

        result = TextPreprocessor.process_evidence(
            "Visit https://example.com"
        )

        assert "https://example.com" not in result["processed_text"]

    def test_verification_disclaimer_present(self):

        result = TextPreprocessor.process_evidence(
            "Suspicious evidence"
        )

        assert "No external reputation verification" in (
            result["disclaimer"]
        )


# =========================================================
# END OF TEST SUITE
# =========================================================