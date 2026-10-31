
"""
====================================================
SCAMSHIELD AI - TEXT PREPROCESSING ENGINE
====================================================

Responsibilities:
- Text normalization
- URL detection and masking
- Email detection and masking
- Phone number masking
- UPI ID masking
- Currency and number normalization
- ML-compatible text preparation

Note:
Original evidence is never modified.
Sensitive values are masked only in processed text.
====================================================
"""

import re
import unicodedata
from typing import Dict, List, Optional


class TextPreprocessor:
    """Preprocess suspicious text for fraud detection."""

    URL_PATTERN = re.compile(
        r"\b(?:https?://|www\.)[^\s<>\"']+",
        re.IGNORECASE
    )

    EMAIL_PATTERN = re.compile(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        re.IGNORECASE
    )

    UPI_PATTERN = re.compile(
        r"\b[A-Z0-9._-]{2,}@[A-Z]{2,}\b",
        re.IGNORECASE
    )

    PHONE_PATTERN = re.compile(
        r"(?<!\w)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\w)"
    )

    CURRENCY_PATTERN = re.compile(
        r"(?:₹|rs\.?|inr)\s*[\d,]+(?:\.\d{1,2})?",
        re.IGNORECASE
    )

    NUMBER_PATTERN = re.compile(
        r"\b\d+(?:,\d{3})*(?:\.\d+)?\b"
    )

    @staticmethod
    def normalize_unicode(text: str) -> str:
        """Normalize Unicode characters."""
        return unicodedata.normalize("NFKC", text)

    @staticmethod
    def remove_control_characters(text: str) -> str:
        """Remove unwanted control characters."""
        return "".join(
            char for char in text
            if unicodedata.category(char)[0] != "C"
            or char in "\n\t"
        )

    @classmethod
    def mask_sensitive_information(cls, text: str) -> str:
        """Mask sensitive indicators without exposing their values."""

        text = cls.URL_PATTERN.sub(" URL_TOKEN ", text)
        text = cls.EMAIL_PATTERN.sub(" EMAIL_TOKEN ", text)
        text = cls.UPI_PATTERN.sub(" UPI_TOKEN ", text)
        text = cls.PHONE_PATTERN.sub(" PHONE_TOKEN ", text)
        text = cls.CURRENCY_PATTERN.sub(" CURRENCY_TOKEN ", text)

        return text

    @classmethod
    def normalize_text(cls, text: str) -> str:
        """Normalize text while preserving meaningful fraud keywords."""

        if not isinstance(text, str):
            raise TypeError("Input must be a string.")

        text = cls.normalize_unicode(text)
        text = cls.remove_control_characters(text)
        text = text.lower()

        # Normalize whitespace.
        text = re.sub(r"\s+", " ", text)

        return text.strip()

    @classmethod
    def preprocess(
        cls,
        text: str,
        mask_sensitive: bool = True
    ) -> str:
        """
        Main preprocessing method.

        Args:
            text: Original evidence text.
            mask_sensitive: Whether to mask sensitive indicators.

        Returns:
            Cleaned text suitable for ML processing.
        """

        if not isinstance(text, str):
            raise TypeError("Evidence must be a string.")

        text = cls.normalize_text(text)

        if mask_sensitive:
            text = cls.mask_sensitive_information(text)

        # Replace standalone numbers with a common token.
        text = cls.NUMBER_PATTERN.sub(" NUMBER_TOKEN ", text)

        # Final whitespace cleanup.
        text = re.sub(r"\s+", " ", text)

        return text.strip()

    @classmethod
    def extract_urls(cls, text: str) -> List[str]:
        """Extract URLs from original evidence."""
        if not isinstance(text, str):
            return []

        return cls.URL_PATTERN.findall(text)

    @classmethod
    def extract_emails(cls, text: str) -> List[str]:
        """Extract email addresses from original evidence."""
        if not isinstance(text, str):
            return []

        return cls.EMAIL_PATTERN.findall(text)

    @classmethod
    def extract_upi_ids(cls, text: str) -> List[str]:
        """Extract possible UPI IDs from original evidence."""
        if not isinstance(text, str):
            return []

        return cls.UPI_PATTERN.findall(text)

    @classmethod
    def extract_phone_numbers(cls, text: str) -> List[str]:
        """Extract possible Indian mobile numbers."""
        if not isinstance(text, str):
            return []

        return cls.PHONE_PATTERN.findall(text)

    @classmethod
    def process_evidence(
        cls,
        text: str,
        evidence_type: Optional[str] = None
    ) -> Dict:
        """
        Process evidence and return sanitized ML text
        alongside extracted indicators.

        Extracted indicators are sensitive data.
        Handle and store them securely.
        """

        if not isinstance(text, str):
            raise TypeError("Evidence must be a string.")

        if not text.strip():
            raise ValueError("Evidence cannot be empty.")

        processed_text = cls.preprocess(text)

        indicators = {
            "urls": cls.extract_urls(text),
            "emails": cls.extract_emails(text),
            "upi_ids": cls.extract_upi_ids(text),
            "phone_numbers": cls.extract_phone_numbers(text)
        }

        return {
            "evidence_type": evidence_type,
            "processed_text": processed_text,
            "indicators": indicators,
            "character_count": len(text),
            "processed_character_count": len(processed_text)
        }


# Convenient module-level function.
def preprocess_text(text: str) -> str:
    """Preprocess text using the default configuration."""
    return TextPreprocessor.preprocess(text)
