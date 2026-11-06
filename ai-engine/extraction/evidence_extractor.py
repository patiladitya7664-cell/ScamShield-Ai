"""
====================================================
SCAMSHIELD AI - ADVANCED EVIDENCE EXTRACTION ENGINE
====================================================

Version: 1.1.0

Responsibilities:
    1. Extract URLs.
    2. Extract email addresses.
    3. Extract Indian phone numbers.
    4. Extract possible UPI IDs.
    5. Identify suspicious keywords.
    6. Handle negated suspicious phrases.
    7. Remove duplicate indicators.
    8. Generate structured evidence metadata.
    9. Preserve verification disclaimers.

Important:
    Extracted indicators are UNVERIFIED.

    Their presence alone does not establish fraud.

    No external reputation verification is performed.

====================================================
"""

import re
from typing import Any, Dict, List


class EvidenceExtractor:

    VERSION = "1.1.0"

    MAX_EVIDENCE_LENGTH = 20000

    # =================================================
    # REGULAR EXPRESSIONS
    # =================================================

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
    # Supports:
    # 9876543210
    # +919876543210
    # 919876543210
    # +91 9876543210
    # 98765-43210

    PHONE_PATTERN = re.compile(
        r"(?<!\w)"
        r"(?:\+?91[\s-]?)?"
        r"[6-9](?:[\s-]?\d){9}"
        r"(?!\w)"
    )

    # Possible UPI IDs.
    #
    # Prevents partial email extraction such as:
    # user@gmail from user@gmail.com
    #
    # UPI identifiers remain candidates, not verified IDs.

    UPI_PATTERN = re.compile(
        r"\b[A-Z0-9._-]{2,}@[A-Z]{2,}\b"
        r"(?!\.[A-Z]{2,}\b)",
        re.IGNORECASE
    )

    # =================================================
    # SUSPICIOUS KEYWORDS
    # =================================================

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

    # =================================================
    # NEGATION PATTERNS
    # =================================================

    NEGATION_PATTERN = re.compile(
        r"\b(?:"
        r"do\s+not|"
        r"don't|"
        r"dont|"
        r"never|"
        r"avoid|"
        r"must\s+not|"
        r"should\s+not|"
        r"cannot|"
        r"can't"
        r")\b",
        re.IGNORECASE
    )

    # =================================================
    # DUPLICATE REMOVAL
    # =================================================

    @staticmethod
    def _unique(values: List[str]) -> List[str]:
        """
        Remove duplicates case-insensitively
        while preserving original order and values.
        """

        seen = set()
        result = []

        for value in values:

            normalized = value.lower()

            if normalized not in seen:

                seen.add(normalized)
                result.append(value)

        return result

    # =================================================
    # URL CLEANING
    # =================================================

    @staticmethod
    def _clean_url(url: str) -> str:
        """
        Remove common trailing punctuation.
        """

        return url.rstrip(".,!?;:)]}")

    # =================================================
    # URL EXTRACTION
    # =================================================

    @classmethod
    def extract_urls(cls, text: str) -> List[str]:

        if not isinstance(text, str):
            return []

        matches = cls.URL_PATTERN.findall(text)

        cleaned = [
            cls._clean_url(url)
            for url in matches
        ]

        cleaned = [
            url for url in cleaned
            if url
        ]

        return cls._unique(cleaned)

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
    # PHONE NUMBER EXTRACTION
    # =================================================

    @classmethod
    def extract_phone_numbers(cls, text: str) -> List[str]:
        """
        Extract possible Indian mobile numbers.

        Preserves the original formatting.
        Does not claim phone-number verification.
        """

        if not isinstance(text, str):
            return []

        matches = cls.PHONE_PATTERN.findall(text)

        return cls._unique(matches)

    # =================================================
    # UPI EXTRACTION
    # =================================================

    @classmethod
    def extract_upi_ids(cls, text: str):
        """
        Extract possible UPI identifiers.

        Email addresses are excluded.
        """

        if not isinstance(text, str):
            return []

        matches = cls.UPI_PATTERN.findall(text)

        emails = {
            email.lower()
            for email in cls.extract_emails(text)
        }

        filtered = []

        for value in matches:

            normalized = value.lower()

            if normalized in emails:
                continue

            filtered.append(value)

        return cls._unique(filtered)

    # =================================================
    # NEGATION DETECTION
    # =================================================

    @classmethod
    def _is_negated_match(
        cls,
        text: str,
        match_start: int
    ) -> bool:
        """
        Detect whether a suspicious phrase is preceded
        by a nearby negation.

        Examples:

        Do not share OTP.
        Never pay immediately.
        Avoid sending money now.

        These are warnings or negative instructions,
        not necessarily suspicious requests.
        """

        # Examine only the current sentence.
        previous_text = text[:match_start]

        sentence_parts = re.split(
            r"[.!?\n]",
            previous_text
        )

        current_context = sentence_parts[-1]

        # Limit context to avoid distant negations.
        current_context = current_context[-60:]

        return bool(
            cls.NEGATION_PATTERN.search(current_context)
        )

    # =================================================
    # KEYWORD EXTRACTION
    # =================================================

    @classmethod
    def extract_keywords(
        cls,
        text: str
    ) -> Dict[str, List[str]]:
        """
        Detect suspicious phrases.

        Negated matches are excluded to reduce
        false positives.

        Matching is case-insensitive.
        """

        if not isinstance(text, str):
            return {}

        detected = {}

        for category, keywords in cls.SUSPICIOUS_KEYWORDS.items():

            matched_keywords = []

            for keyword in keywords:

                pattern = re.compile(
                    r"(?<!\w)"
                    + re.escape(keyword)
                    + r"(?!\w)",
                    re.IGNORECASE
                )

                for match in pattern.finditer(text):

                    if cls._is_negated_match(
                        text,
                        match.start()
                    ):
                        continue

                    matched_keywords.append(keyword)
                    break

            if matched_keywords:

                detected[category] = cls._unique(
                    matched_keywords
                )

        return detected

    # =================================================
    # COMPLETE EVIDENCE EXTRACTION
    # =================================================

    @classmethod
    def extract(
        cls,
        evidence: str
    ) -> Dict[str, Any]:
        """
        Extract structured indicators from evidence.

        Args:
            evidence:
                Original user-provided evidence.

        Returns:
            Structured extraction result.
        """

        # Input type validation
        if not isinstance(evidence, str):

            raise TypeError(
                "Evidence must be a string."
            )

        evidence = evidence.strip()

        # Empty input validation
        if not evidence:

            raise ValueError(
                "Evidence cannot be empty."
            )

        # Maximum length validation
        if len(evidence) > cls.MAX_EVIDENCE_LENGTH:

            raise ValueError(
                f"Evidence exceeds maximum length of "
                f"{cls.MAX_EVIDENCE_LENGTH} characters."
            )

        # ---------------------------------------------
        # Extract indicators
        # ---------------------------------------------

        indicators = {

            "urls": cls.extract_urls(evidence),

            "emails": cls.extract_emails(evidence),

            "phone_numbers": cls.extract_phone_numbers(
                evidence
            ),

            "upi_ids": cls.extract_upi_ids(evidence)
        }

        # ---------------------------------------------
        # Extract suspicious keywords
        # ---------------------------------------------

        suspicious_keywords = cls.extract_keywords(
            evidence
        )

        # ---------------------------------------------
        # Calculate indicator count
        # ---------------------------------------------

        indicator_count = sum(
            len(values)
            for values in indicators.values()
        )

        # ---------------------------------------------
        # Response
        # ---------------------------------------------

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
                "Their presence does not independently "
                "prove fraud. No external reputation "
                "verification has been performed."
            )
        }


# =====================================================
# MODULE-LEVEL FUNCTION
# =====================================================

def extract_evidence(
    evidence: str
) -> Dict[str, Any]:
    """
    Convenient public extraction function.
    """

    return EvidenceExtractor.extract(evidence)