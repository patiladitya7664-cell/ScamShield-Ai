
"""
====================================================
SCAMSHIELD AI - EVIDENCE EXTRACTION ENGINE
====================================================

Responsibilities:
- Extract URLs
- Extract email addresses
- Extract Indian phone numbers
- Extract possible UPI IDs
- Identify suspicious keywords
- Generate structured evidence metadata

Note:
Extracted indicators are unverified.
Their presence alone does not establish fraud.
====================================================
"""

import re
from typing import Any, Dict, List


class EvidenceExtractor:

    MAX_EVIDENCE_LENGTH = 20000

    # URL extraction
    URL_PATTERN = re.compile(
        r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
    )

    # Email extraction
    EMAIL_PATTERN = re.compile(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        re.IGNORECASE
    )

    # Indian mobile numbers
    PHONE_PATTERN = re.compile(
        r"(?<!\w)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\w)"
    )

    # Possible UPI IDs
    UPI_PATTERN = re.compile(
        r"\b[A-Z0-9._-]{2,}@[A-Z]{2,}\b",
        re.IGNORECASE
    )

    # Common fraud-related keywords
    SUSPICIOUS_KEYWORDS = {
        "urgent_payment": [
            "pay immediately",
            "urgent payment",
            "send money now",
            "immediate transfer"
        ],
        "otp_request": [
            "share otp",
            "send otp",
            "otp verification",
            "tell me your otp"
        ],
        "threats": [
            "arrest warrant",
            "police case",
            "account blocked",
            "legal action",
            "digital arrest"
        ],
        "investment_scam": [
            "guaranteed returns",
            "double your money",
            "risk free investment",
            "daily profit"
        ],
        "remote_access": [
            "install anydesk",
            "install teamviewer",
            "remote access",
            "screen sharing"
        ],
        "prize_scam": [
            "you have won",
            "claim your prize",
            "lottery winner",
            "claim reward"
        ]
    }

    @staticmethod
    def _unique(values: List[str]) -> List[str]:
        """Remove duplicates while preserving order."""

        seen = set()
        result = []

        for value in values:
            normalized = value.lower()

            if normalized not in seen:
                seen.add(normalized)
                result.append(value)

        return result

    @staticmethod
    def _clean_url(url: str) -> str:
        """Remove common trailing punctuation from URLs."""

        return url.rstrip(".,!?;:)]}")

    @classmethod
    def extract_urls(cls, text: str) -> List[str]:

        matches = cls.URL_PATTERN.findall(text)

        cleaned = [
            cls._clean_url(url)
            for url in matches
        ]

        return cls._unique(cleaned)

    @classmethod
    def extract_emails(cls, text: str) -> List[str]:

        matches = cls.EMAIL_PATTERN.findall(text)

        return cls._unique(matches)

    @classmethod
    def extract_phone_numbers(cls, text: str) -> List[str]:

        matches = cls.PHONE_PATTERN.findall(text)

        return cls._unique(matches)

    @classmethod
    def extract_upi_ids(cls, text: str) -> List[str]:

        matches = cls.UPI_PATTERN.findall(text)

        # Remove values that are actually email addresses.
        emails = {
            email.lower()
            for email in cls.extract_emails(text)
        }

        matches = [
            value
            for value in matches
            if value.lower() not in emails
        ]

        return cls._unique(matches)

    @classmethod
    def extract_keywords(cls, text: str) -> Dict[str, List[str]]:
        """Find matching fraud-related phrases."""

        normalized_text = text.lower()
        detected = {}

        for category, keywords in cls.SUSPICIOUS_KEYWORDS.items():

            matches = [
                keyword
                for keyword in keywords
                if keyword in normalized_text
            ]

            if matches:
                detected[category] = matches

        return detected

    @classmethod
    def extract(cls, evidence: str) -> Dict[str, Any]:
        """
        Extract structured indicators from evidence.

        Args:
            evidence: Original user-provided evidence.

        Returns:
            Structured extraction result.
        """

        if not isinstance(evidence, str):
            raise TypeError("Evidence must be a string.")

        evidence = evidence.strip()

        if not evidence:
            raise ValueError("Evidence cannot be empty.")

        if len(evidence) > cls.MAX_EVIDENCE_LENGTH:
            raise ValueError(
                f"Evidence exceeds maximum length of "
                f"{cls.MAX_EVIDENCE_LENGTH} characters."
            )

        indicators = {
            "urls": cls.extract_urls(evidence),
            "emails": cls.extract_emails(evidence),
            "phone_numbers": cls.extract_phone_numbers(evidence),
            "upi_ids": cls.extract_upi_ids(evidence)
        }

        suspicious_keywords = cls.extract_keywords(evidence)

        indicator_count = sum(
            len(values)
            for values in indicators.values()
        )

        return {
            "success": True,
            "indicators": indicators,
            "suspicious_keywords": suspicious_keywords,
            "indicator_count": indicator_count,
            "keyword_categories_detected": list(
                suspicious_keywords.keys()
            ),
            "evidence_length": len(evidence),
            "verification_status": "UNVERIFIED",
            "disclaimer": (
                "Extracted indicators are unverified. "
                "Their presence does not independently prove fraud."
            )
        }


# Convenient module-level function.
def extract_evidence(evidence: str) -> Dict[str, Any]:

    return EvidenceExtractor.extract(evidence)
