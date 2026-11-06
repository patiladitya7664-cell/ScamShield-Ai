"""
====================================================
SCAMSHIELD AI - ADVANCED TEXT PREPROCESSING ENGINE
====================================================

Version: 2.0.0

Responsibilities:
    1. Unicode normalization.
    2. Text normalization.
    3. URL extraction and masking.
    4. Email extraction and masking.
    5. Indian phone number extraction and masking.
    6. Possible UPI ID extraction and masking.
    7. PAN and Aadhaar-like number masking.
    8. Payment card number masking.
    9. Currency and number normalization.
    10. ML-compatible text preparation.
    11. Evidence metadata generation.

Security:
    - Original evidence is never modified.
    - Sensitive values are masked in processed text.
    - Extracted indicators remain UNVERIFIED.
    - No external reputation verification is performed.

====================================================
"""

import re
import unicodedata

from typing import Any, Dict, List, Optional


class TextPreprocessor:
    """Preprocess suspicious evidence for fraud detection."""

    VERSION = "2.0.0"

    MAX_EVIDENCE_LENGTH = 20000

    SUPPORTED_EVIDENCE_TYPES = {
        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email"
    }

    # =================================================
    # REGULAR EXPRESSIONS
    # =================================================

    URL_PATTERN = re.compile(
        r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
    )

    EMAIL_PATTERN = re.compile(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        re.IGNORECASE
    )

    UPI_PATTERN = re.compile(
        r"(?<![\w.+-])"
        r"[A-Z0-9._-]{2,}"
        r"@[A-Z]{2,}"
        r"(?![\w.-])",
        re.IGNORECASE
    )

    # Indian mobile numbers with optional country code.
    # Supports:
    # 9876543210
    # +919876543210
    # 919876543210
    # +91 98765 43210
    # 98765-43210

    PHONE_PATTERN = re.compile(
        r"(?<!\w)"
        r"(?:\+?91[\s-]?)?"
        r"[6-9](?:[\s-]?\d){9}"
        r"(?!\w)"
    )

    CURRENCY_PATTERN = re.compile(
        r"""
        (?:
            ₹
            |
            \b(?:rs\.?|inr)\b
        )
        \s*
        \d[\d,]*
        (?:\.\d{1,2})?
        """,
        re.IGNORECASE | re.VERBOSE
    )

    # PAN-like identifier.
    PAN_PATTERN = re.compile(
        r"\b[A-Z]{5}\d{4}[A-Z]\b",
        re.IGNORECASE
    )

    # Aadhaar-like 12-digit sequence.
    AADHAAR_PATTERN = re.compile(
        r"(?<!\d)"
        r"\d{4}[\s-]?\d{4}[\s-]?\d{4}"
        r"(?!\d)"
    )

    # Payment card-like number.
    CARD_PATTERN = re.compile(
        r"(?<!\d)"
        r"\d(?:[\s-]?\d){12,18}"
        r"(?!\d)"
    )

    # Standalone numbers.
    NUMBER_PATTERN = re.compile(
        r"(?<!\w)"
        r"\d+(?:,\d{3})*(?:\.\d+)?"
        r"(?!\w)"
    )

    # =================================================
    # INPUT VALIDATION
    # =================================================

    @classmethod
    def _validate_text(cls, text: str) -> None:

        if not isinstance(text, str):

            raise TypeError(
                "Evidence must be a string."
            )

        if not text.strip():

            raise ValueError(
                "Evidence cannot be empty."
            )

        if len(text) > cls.MAX_EVIDENCE_LENGTH:

            raise ValueError(
                f"Evidence exceeds maximum length of "
                f"{cls.MAX_EVIDENCE_LENGTH} characters."
            )

    # =================================================
    # UNICODE NORMALIZATION
    # =================================================

    @staticmethod
    def normalize_unicode(text: str) -> str:
        """
        Normalize compatible Unicode characters.

        Preserves meaningful language content,
        including Hindi and Hinglish text.
        """

        return unicodedata.normalize("NFKC", text)

    # =================================================
    # CONTROL CHARACTER REMOVAL
    # =================================================

    @staticmethod
    def remove_control_characters(text: str) -> str:
        """
        Remove unwanted Unicode control and formatting
        characters while preserving newlines and tabs.
        """

        result = []

        for char in text:

            category = unicodedata.category(char)

            if category in ("Cc", "Cf", "Cs", "Co", "Cn"):

                if char in ("\n", "\t"):
                    result.append(char)

                continue

            result.append(char)

        return "".join(result)

    # =================================================
    # URL CLEANING
    # =================================================

    @staticmethod
    def _clean_url(url: str) -> str:
        """
        Remove trailing punctuation without removing
        balanced URL parentheses.
        """

        url = url.rstrip(".,!?;:")

        while url.endswith((")", "]", "}")):

            closing = url[-1]

            opening = {
                ")": "(",
                "]": "[",
                "}": "{"
            }[closing]

            if url.count(closing) > url.count(opening):
                url = url[:-1]

            else:
                break

        return url

    # =================================================
    # UNIQUE VALUES
    # =================================================

    @staticmethod
    def _unique(values: List[str]) -> List[str]:
        """
        Remove duplicate values case-insensitively.
        Preserve original order and formatting.
        """

        seen = set()
        result = []

        for value in values:

            normalized = value.casefold()

            if normalized not in seen:

                seen.add(normalized)
                result.append(value)

        return result

    # =================================================
    # URL EXTRACTION
    # =================================================

    @classmethod
    def extract_urls(cls, text: str) -> List[str]:

        if not isinstance(text, str):
            return []

        matches = cls.URL_PATTERN.findall(text)

        cleaned = [
            cls._clean_url(value)
            for value in matches
        ]

        return cls._unique([
            value for value in cleaned if value
        ])

    # =================================================
    # EMAIL EXTRACTION
    # =================================================

    @classmethod
    def extract_emails(cls, text: str) -> List[str]:

        if not isinstance(text, str):
            return []

        matches = cls.EMAIL_PATTERN.findall(text)

        return cls._unique(matches)

    # =================================================
    # UPI EXTRACTION
    # =================================================

    @classmethod
    def extract_upi_ids(cls, text: str) -> List[str]:
        """
        Extract possible UPI identifiers.

        Excludes:
            - Email addresses.
            - Matches overlapping with URLs.

        Extracted values remain unverified.
        """

        if not isinstance(text, str):
            return []

        email_spans = [
            match.span()
            for match in cls.EMAIL_PATTERN.finditer(text)
        ]

        url_spans = [
            match.span()
            for match in cls.URL_PATTERN.finditer(text)
        ]

        excluded_spans = email_spans + url_spans

        results = []

        for match in cls.UPI_PATTERN.finditer(text):

            start, end = match.span()

            overlaps = any(
                start < excluded_end
                and end > excluded_start
                for excluded_start, excluded_end
                in excluded_spans
            )

            if not overlaps:

                results.append(match.group())

        return cls._unique(results)

    # =================================================
    # PHONE EXTRACTION
    # =================================================

    @classmethod
    def extract_phone_numbers(cls, text: str) -> List[str]:
        """
        Extract possible Indian mobile numbers.

        Original formatting is preserved.
        """

        if not isinstance(text, str):
            return []

        matches = cls.PHONE_PATTERN.findall(text)

        return cls._unique(matches)

    # =================================================
    # SENSITIVE INFORMATION MASKING
    # =================================================

    @classmethod
    def mask_sensitive_information(
        cls,
        text: str
    ) -> str:
        """
        Mask sensitive values in processed text.

        Original evidence remains unchanged.
        """

        if not isinstance(text, str):

            raise TypeError(
                "Input must be a string."
            )

        # Mask URLs first.
        text = cls.URL_PATTERN.sub(
            " URL_TOKEN ",
            text
        )

        # Mask email addresses before UPI identifiers.
        text = cls.EMAIL_PATTERN.sub(
            " EMAIL_TOKEN ",
            text
        )

        # Mask possible UPI identifiers.
        text = cls.UPI_PATTERN.sub(
            " UPI_TOKEN ",
            text
        )

        # Mask phone numbers.
        text = cls.PHONE_PATTERN.sub(
            " PHONE_TOKEN ",
            text
        )

        # Mask payment card-like numbers.
        text = cls.CARD_PATTERN.sub(
            " CARD_TOKEN ",
            text
        )

        # Mask Aadhaar-like numbers.
        text = cls.AADHAAR_PATTERN.sub(
            " AADHAAR_TOKEN ",
            text
        )

        # Mask PAN-like identifiers.
        text = cls.PAN_PATTERN.sub(
            " PAN_TOKEN ",
            text
        )

        # Mask currency values.
        text = cls.CURRENCY_PATTERN.sub(
            " CURRENCY_TOKEN ",
            text
        )

        return text

    # =================================================
    # TEXT NORMALIZATION
    # =================================================

    @classmethod
    def normalize_text(cls, text: str) -> str:
        """
        Normalize text while preserving meaningful
        fraud-related language and context.
        """

        if not isinstance(text, str):

            raise TypeError(
                "Input must be a string."
            )

        text = cls.normalize_unicode(text)

        text = cls.remove_control_characters(text)

        text = text.lower()

        text = re.sub(
            r"\s+",
            " ",
            text
        )

        return text.strip()

    # =================================================
    # MAIN PREPROCESSING
    # =================================================

    @classmethod
    def preprocess(
        cls,
        text: str,
        mask_sensitive: bool = True
    ) -> str:
        """
        Prepare text for ML processing.

        Args:
            text:
                Original evidence.

            mask_sensitive:
                Whether sensitive values should be masked.

        Returns:
            Normalized processed text.
        """

        cls._validate_text(text)

        if not isinstance(mask_sensitive, bool):

            raise TypeError(
                "mask_sensitive must be a boolean."
            )

        processed = cls.normalize_text(text)

        if mask_sensitive:

            processed = cls.mask_sensitive_information(
                processed
            )

        # Normalize remaining standalone numbers.
        processed = cls.NUMBER_PATTERN.sub(
            " NUMBER_TOKEN ",
            processed
        )

        # Final whitespace normalization.
        processed = re.sub(
            r"\s+",
            " ",
            processed
        )

        return processed.strip()

    # =================================================
    # COMPLETE EVIDENCE PROCESSING
    # =================================================

    @classmethod
    def process_evidence(
        cls,
        text: str,
        evidence_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Process evidence and return:

            1. Processed ML text.
            2. Extracted indicators.
            3. Evidence metadata.

        Raw indicators must be handled securely.
        """

        cls._validate_text(text)

        # Validate evidence type.
        if evidence_type is not None:

            if not isinstance(evidence_type, str):

                raise TypeError(
                    "Evidence type must be a string."
                )

            evidence_type = evidence_type.strip().lower()

            if evidence_type not in cls.SUPPORTED_EVIDENCE_TYPES:

                raise ValueError(
                    f"Unsupported evidence type: {evidence_type}"
                )

        # Processed text.
        processed_text = cls.preprocess(text)

        # Extract original indicators.
        indicators = {

            "urls": cls.extract_urls(text),

            "emails": cls.extract_emails(text),

            "upi_ids": cls.extract_upi_ids(text),

            "phone_numbers": cls.extract_phone_numbers(text)
        }

        indicator_count = sum(
            len(values)
            for values in indicators.values()
        )

        return {

            "success": True,

            "version": cls.VERSION,

            "evidence_type": evidence_type,

            "processed_text": processed_text,

            "indicators": indicators,

            "indicator_count": indicator_count,

            "character_count": len(text),

            "processed_character_count": len(
                processed_text
            ),

            "verification_status": "UNVERIFIED",

            "disclaimer": (
                "Extracted indicators are unverified. "
                "Their presence does not independently "
                "prove fraud. No external reputation "
                "verification has been performed."
            )
        }


# =====================================================
# MODULE-LEVEL FUNCTION
# =====================================================

def preprocess_text(text: str) -> str:
    """
    Convenient public preprocessing function.
    """

    return TextPreprocessor.preprocess(text)