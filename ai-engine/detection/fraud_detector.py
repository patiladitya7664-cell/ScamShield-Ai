"""
=========================================================
SCAMSHIELD AI - ADVANCED HYBRID FRAUD DETECTOR
=========================================================

Version: 3.4.0

Capabilities:
    1. Text preprocessing
    2. Evidence extraction
    3. Evidence-type-aware detection
    4. 12-category fraud classification
    5. Priority-based primary category selection
    6. Multiple-category detection
    7. Context-aware rule detection
    8. Credential harvesting detection
    9. Suspicious URL and domain heuristics
    10. RiskScorer integration
    11. Optional ML prediction
    12. Explainable detection results
    13. Privacy-aware indicator sanitization
    14. Graceful ML and extraction failure handling
    15. Input validation

IMPORTANT:
    Call evidence means supplied call transcript/text.
    Screenshot evidence means supplied extracted text.
    No automatic audio transcription or screenshot OCR.
    URL analysis is heuristic; no live reputation check.
    ML predictions are advisory only.
    Risk score is not a calibrated probability.

=========================================================
"""

import ipaddress
import math
import re

from pathlib import Path
from urllib.parse import urlparse

import joblib

from utils.text_preprocessor import TextPreprocessor
from utils.risk_scorer import RiskScorer
from extraction.evidence_extractor import EvidenceExtractor
from utils.logger import logger


class FraudDetector:

    VERSION = "3.4.0"
    MAX_EVIDENCE_LENGTH = 20000

    SUPPORTED_EVIDENCE_TYPES = {
        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",
    }

    CATEGORY_PRIORITY = [
        "digital_arrest",
        "sextortion_blackmail",
        "investment_scam",
        "card_fraud",
        "upi_banking_fraud",
        "url_phishing",
        "email_scam",
        "fraud_call",
        "ecommerce_scam",
        "job_loan_scam",
        "social_media_scam",
        "fraud_message",
    ]

    MODEL_PATH = (
        Path(__file__).resolve().parents[1]
        / "models"
        / "fraud_model.joblib"
    )

    # =====================================================
    # URL CONFIGURATION
    # =====================================================

    URL_PATTERN = re.compile(
        r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
        re.IGNORECASE,
    )

    URL_CONTEXT_PATTERNS = [
        r"\bclick\s+(?:this|the)\s+link\b",
        r"\bverify\s+your\s+account\b",
        r"\bconfirm\s+your\s+(?:account|identity|details)\b",
        r"\baccount\s+(?:will\s+be\s+)?suspended\b",
        r"\baccount\s+(?:will\s+be\s+)?blocked\b",
        r"\bupdate\s+your\s+(?:bank|account|kyc)\b",
        r"\blogin\s+immediately\b",
        r"\brestore\s+your\s+account\b",
        r"\bsecure\s+your\s+account\b",
        r"\bopen\s+this\s+link\b",
        r"\bvisit\s+this\s+link\b",
        r"\bverify\s+immediately\b",
        r"\benter\s+your\s+(?:password|otp|pin)\b",
    ]

    CREDENTIAL_PATTERNS = [
        r"\b(?:share|send|provide|enter|submit|reveal)\s+(?:your\s+)?(?:otp|one[\s-]?time\s+password)\b",

        r"\b(?:otp|one[\s-]?time\s+password)\s+(?:is\s+required|verification|required)\b",

        r"\b(?:share|send|provide|enter|submit|reveal)\s+(?:your\s+)?(?:password|passcode)\b",

        r"\b(?:internet|net|online|mobile)\s+banking\s+(?:username|password|credentials|login\s+details)\b",

        r"\busername\s*(?:and|&|,)\s*password\b",

        r"\b(?:enter|provide|submit|share)\s+(?:your\s+)?(?:login\s+credentials|banking\s+credentials)\b",

        r"\b(?:banking|internet\s+banking)\s+(?:username|password)\s+and\s+(?:password|otp|pin)\b",

        r"\b(?:share|send|provide|enter|submit)\s+(?:your\s+)?(?:upi\s+pin|atm\s+pin|card\s+pin)\b",

        r"\benter\s+(?:your\s+)?pin\s+to\s+receive\s+money\b",

        r"\b(?:share|send|provide|enter)\s+(?:your\s+)?(?:cvv|cvc|card\s+details)\b",

        r"\b(?:credit|debit)\s+card\s+(?:number|details|cvv|pin)\b",

        # Victim-reported credential requests.
        r"\b(?:scammer|fraudster)\s+(?:asked|told)\s+me\s+to\s+(?:share|send|provide|reveal|enter|submit)\s+(?:my|the)\s+(?:otp|one[\s-]?time\s+password|password|passcode|pin|cvv)\b",

        r"\b(?:scammer|fraudster)\s+(?:asked|requested)\s+me\s+for\s+(?:my\s+)?(?:otp|one[\s-]?time\s+password|password|pin|cvv)\b",

        r"\b(?:they|he|she)\s+(?:asked|told)\s+me\s+to\s+(?:share|send|provide|reveal|enter|submit)\s+(?:my|the)\s+(?:otp|one[\s-]?time\s+password|password|pin|cvv)\b",
    ]

    SHORTENED_DOMAINS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "tiny.cc",
        "is.gd",
        "shorturl.at",
        "cutt.ly",
        "rb.gy",
        "rebrand.ly",
        "ow.ly",
        "buff.ly",
    }

    PROTECTED_BRANDS = {
        "sbi",
        "hdfc",
        "icici",
        "axisbank",
        "kotak",
        "paytm",
        "phonepe",
        "google",
        "microsoft",
        "amazon",
        "flipkart",
        "instagram",
        "facebook",
        "whatsapp",
        "rbi",
    }

    SUSPICIOUS_DOMAIN_KEYWORDS = {
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "login",
        "kyc",
        "banking",
        "wallet",
        "support",
        "refund",
        "claim",
        "reward",
        "authenticate",
    }

    # =====================================================
    # CONTEXT DETECTION
    # =====================================================

    VICTIM_REPORT_PATTERNS = [
        r"\bthe scammer\b",
        r"\bscammer asked\b",
        r"\bfraudster asked\b",
        r"\bthey asked me\b",
        r"\bhe asked me\b",
        r"\bshe asked me\b",
        r"\bi was asked\b",
        r"\bi received\b",
        r"\bi got a message\b",
        r"\bsomeone asked me\b",
        r"\bthey told me to\b",
        r"\bi shared my\b",
        r"\bi entered my\b",
        r"\bi already shared\b",
        r"\bi already entered\b",
        r"\bi accidentally shared\b",
    ]

    EDUCATIONAL_PATTERNS = [
        r"\bthis article\b",
        r"\bthis tutorial\b",
        r"\beducational purpose\b",
        r"\bfor educational purposes\b",
        r"\bawareness campaign\b",
        r"\bsecurity awareness\b",
        r"\bexplains how\b",
        r"\bguide to identifying\b",
        r"\bhow to recognize\b",
        r"\bhow to prevent\b",
        r"\blearn about\b",
        r"\bexample of a scam\b",
        r"\bscam awareness\b",
    ]

    ADVISORY_PATTERNS = [
        r"\bnever\s+(?:share|send|provide|reveal|enter|submit)\b",
        r"\bdo not\s+(?:share|send|provide|reveal|enter|submit)\b",
        r"\bdon't\s+(?:share|send|provide|reveal|enter|submit)\b",
        r"\bshould not\s+(?:share|send|provide|reveal|enter|submit)\b",
        r"\bmust not\s+(?:share|send|provide|reveal|enter|submit)\b",
        r"\bavoid\s+(?:sharing|sending|providing|revealing)\b",
    ]

    # =====================================================
    # 12 FRAUD CATEGORIES
    # =====================================================

    FRAUD_CATEGORIES = {

        "fraud_message": {
            "name": "Fraud Message Detection",
            "patterns": [
                r"\bfake sms\b",
                r"\bfraud message\b",
                r"\bsuspicious message\b",
                r"\bshare your otp\b",
                r"\bclaim your reward\b",
                r"\bpay immediately\b",
                r"\baccount will be blocked\b",
                r"\bclick this link\b",
                r"\bverify your account immediately\b",
                r"\baccount will be suspended\b",
            ],
        },

        "fraud_call": {
            "name": "Fraud Call Detection",
            "patterns": [
                r"\bfraud call\b",
                r"\bfake bank call\b",
                r"\bi am calling from the bank\b",
                r"\bcalling from your bank\b",
                r"\bcall based otp\b",
                r"\bvoice impersonation\b",
                r"\bfake police call\b",
                r"\bvideo call.*arrest\b",
                r"\bcalling from the police\b",
                r"\bcalling from the cbi\b",
            ],
        },

        "url_phishing": {
            "name": "URL & Phishing Detection",
            "patterns": [
                r"\bphishing\b",
                r"\bverify your account through\b",
                r"\bclick this link\b",
                r"\bunknown login link\b",
                r"\bfake login page\b",
                r"\bcredential harvesting\b",
                r"\bpassword verification\b",
                r"\baccount suspended.*link\b",
                r"\bverify.*https?://",
                r"\benter your (?:password|otp|pin).*https?://",
                r"\brestore your account.*https?://",
            ],
        },

        "email_scam": {
            "name": "Email Scam Detection",
            "patterns": [
                r"\bemail phishing\b",
                r"\bfake email\b",
                r"\bsuspicious email\b",
                r"\bemail spoofing\b",
                r"\bverify your account.*email\b",
                r"\bsuspicious reply-to\b",
                r"\bsender address mismatch\b",
                r"\bemail attachment\b",
            ],
        },

        "investment_scam": {
            "name": "Investment Scam Detection",
            "patterns": [
                r"\bguaranteed returns\b",
                r"\bguaranteed profit\b",
                r"\bdouble your money\b",
                r"\bno risk investment\b",
                r"\bcrypto investment\b",
                r"\btrading profit\b",
                r"\bdaily profit guaranteed\b",
                r"\bponzi scheme\b",
                r"\binvestment withdrawal fee\b",
                r"\bget rich quickly\b",
                r"\b100 percent return\b",
            ],
        },

        "digital_arrest": {
            "name": "Digital Arrest Detection",
            "patterns": [
                r"\bdigital arrest\b",
                r"\bvirtual arrest\b",
                r"\byou are under arrest\b",
                r"\bcbi officer\b",
                r"\bcustoms department\b",
                r"\bpolice officer.*video call\b",
                r"\bcase registered against you\b",
                r"\bimmediate detention\b",
                r"\bthreatened.*arrest\b",
                r"\bremain on video call\b",
                r"\bvideo call.*investigation\b",
            ],
        },

        "upi_banking_fraud": {
            "name": "UPI & Banking Fraud Detection",
            "patterns": [
                r"\bapprove collect request\b",
                r"\baccept upi request\b",
                r"\bscan qr to receive money\b",
                r"\benter pin to receive\b",
                r"\bupi collect\b",
                r"\bbanking password\b",
                r"\bnet banking credentials\b",
                r"\bfake bank verification\b",
                r"\bunauthorized payment\b",
                r"\bbank account blocked\b",
                r"\bupdate bank kyc immediately\b",
            ],
        },

        "card_fraud": {
            "name": "Credit/Debit Card Fraud Detection",
            "patterns": [
                r"\bshare your cvv\b",
                r"\bprovide your cvv\b",
                r"\bsend your card pin\b",
                r"\bshare your card pin\b",
                r"\bcard verification.*otp\b",
                r"\bshare your card details\b",
                r"\bcredit card blocked.*verify\b",
                r"\bdebit card blocked.*verify\b",
                r"\bcard cvv\b",
                r"\bcredit card number\b",
            ],
        },

        "ecommerce_scam": {
            "name": "E-commerce Scam Detection",
            "patterns": [
                r"\bfake shopping website\b",
                r"\bfake seller\b",
                r"\bpayment before delivery\b",
                r"\bparcel delivery charge\b",
                r"\border refund fee\b",
                r"\bfake product delivery\b",
                r"\bonline shopping scam\b",
                r"\bfake customer support\b",
                r"\badvance payment.*product\b",
                r"\bpay to release parcel\b",
            ],
        },

        "job_loan_scam": {
            "name": "Job & Loan Scam Detection",
            "patterns": [
                r"\bjob registration fee\b",
                r"\bjob confirmation fee\b",
                r"\bpay to get selected\b",
                r"\bguaranteed job placement\b",
                r"\bjob processing fee\b",
                r"\bloan processing fee\b",
                r"\badvance loan fee\b",
                r"\bpay before loan approval\b",
                r"\bloan release charge\b",
                r"\bguaranteed loan approval\b",
            ],
        },

        "sextortion_blackmail": {
            "name": "Sextortion & Blackmail Detection",
            "patterns": [
                r"\bsextortion\b",
                r"\bblackmail\b",
                r"\bpay or i will expose\b",
                r"\bintimate video\b",
                r"\bprivate photos\b",
                r"\bexpose your photos\b",
                r"\bviral your video\b",
                r"\bthreat to expose\b",
                r"\bprivate pictures\b",
            ],
        },

        "social_media_scam": {
            "name": "Social Media Scam Detection",
            "patterns": [
                r"\bfake profile\b",
                r"\bfake instagram account\b",
                r"\binstagram giveaway\b",
                r"\bsocial media impersonation\b",
                r"\bfake influencer\b",
                r"\bfollower giveaway\b",
                r"\bfake social media account\b",
                r"\bsocial media phishing\b",
                r"\bfake facebook profile\b",
                r"\bimpersonation account\b",
            ],
        },
    }

    # =====================================================
    # RULE-BASED DETECTION
    # =====================================================

    RULES = {

        "urgent_payment": {
            "patterns": [
                r"\bpay immediately\b",
                r"\bpay now\b",
                r"\burgent payment\b",
                r"\btransfer money now\b",
                r"\bmake an instant payment\b",
                r"\bpayment required immediately\b",
                r"\bact immediately\b",
                r"\blimited time offer\b",
                r"\bdo it right now\b",
            ],
            "signal": "urgent_payment",
            "description": "Urgent payment language detected.",
        },

        "threat_or_intimidation": {
            "patterns": [
                r"\barrest\b",
                r"\bpolice case\b",
                r"\blegal action\b",
                r"\baccount will be blocked\b",
                r"\bconnection will be disconnected\b",
                r"\byou will be arrested\b",
                r"\bdigital arrest\b",
                r"\bcase registered against you\b",
                r"\bimmediate detention\b",
                r"\bcbi investigation\b",
            ],
            "signal": "threat_or_intimidation",
            "description": "Threat or intimidation language detected.",
        },

        "otp_or_credential_request": {
            "patterns": CREDENTIAL_PATTERNS,
            "signal": "otp_or_credential_request",
            "description": "Sensitive credential request detected.",
        },

        "impersonation": {
            "patterns": [
                r"\bwe are from your bank\b",
                r"\bi am calling from the bank\b",
                r"\bpolice officer\b",
                r"\bgovernment officer\b",
                r"\bcustoms department\b",
                r"\bincome tax department\b",
                r"\brbi officer\b",
                r"\bcbi officer\b",
                r"\btelecom department\b",
                r"\bgovernment authority\b",
            ],
            "signal": "impersonation",
            "description": "Possible organization impersonation detected.",
        },

        "suspicious_link": {
            "patterns": [
                r"\bclick this link\b",
                r"\bverify through this link\b",
                r"\bopen this link immediately\b",
                r"\bunknown payment link\b",
                r"\bsuspicious payment link\b",
                r"\bbit\.ly\b",
                r"\btinyurl\.com\b",
                r"\bshorturl\.at\b",
            ],
            "signal": "suspicious_link",
            "description": "Suspicious link context detected.",
        },

        "unrealistic_reward": {
            "patterns": [
                r"\byou have won\b",
                r"\bfree cash prize\b",
                r"\bclaim your reward\b",
                r"\blottery winner\b",
                r"\bprocessing fee\b",
                r"\bguaranteed prize\b",
                r"\bcongratulations.*winner\b",
                r"\bprize money\b",
            ],
            "signal": "unrealistic_reward",
            "description": "Possible fake reward or prize tactic detected.",
        },

        "financial_pressure": {
            "patterns": [
                r"\bpay a fee to unlock\b",
                r"\btransfer money to avoid\b",
                r"\bsend money immediately\b",
                r"\bpay registration fee\b",
                r"\bpay to release\b",
                r"\badvance payment required\b",
                r"\brefund processing fee\b",
                r"\bsecurity deposit required\b",
            ],
            "signal": "financial_pressure",
            "description": "Financial pressure tactic detected.",
        },

        "remote_access_request": {
            "patterns": [
                r"\binstall remote access\b",
                r"\binstall anydesk\b",
                r"\binstall teamviewer\b",
                r"\bgrant remote access\b",
                r"\bshare your screen\b",
                r"\bdownload remote support\b",
                r"\bremote desktop access\b",
            ],
            "signal": "remote_access_request",
            "description": "Remote access request detected.",
        },

        "identity_document_request": {
            "patterns": [
                r"\bsend your aadhaar\b",
                r"\bshare your pan card\b",
                r"\bupload identity proof\b",
                r"\bsend your identity document\b",
                r"\baadhaar verification\b",
                r"\bpan card details\b",
                r"\bpassport details\b",
            ],
            "signal": "identity_document_request",
            "description": "Identity document request detected.",
        },

        "investment_guarantee": {
            "patterns": [
                r"\bguaranteed returns\b",
                r"\bguaranteed profit\b",
                r"\bno risk investment\b",
                r"\bdouble your money\b",
                r"\bhigh returns guaranteed\b",
                r"\b100 percent return\b",
                r"\bdaily profit guaranteed\b",
                r"\bget rich quickly\b",
            ],
            "signal": "investment_guarantee",
            "description": "Unrealistic investment promise detected.",
        },

        "upi_payment_manipulation": {
            "patterns": [
                r"\bapprove collect request\b",
                r"\baccept upi request\b",
                r"\bscan qr to receive money\b",
                r"\benter pin to receive\b",
                r"\bupi collect\b",
                r"\brequest money\b",
                r"\bpayment approval request\b",
            ],
            "signal": "upi_payment_manipulation",
            "description": "Possible UPI payment manipulation detected.",
        },

        "fake_job_offer": {
            "patterns": [
                r"\bpay registration fee for job\b",
                r"\bjob confirmation fee\b",
                r"\bwork from home.*registration fee\b",
                r"\bguaranteed job placement\b",
                r"\bpay to get selected\b",
                r"\bjob processing fee\b",
            ],
            "signal": "fake_job_offer",
            "description": "Possible fraudulent job offer detected.",
        },

        "loan_fee_scam": {
            "patterns": [
                r"\bloan processing fee\b",
                r"\bpay before loan approval\b",
                r"\badvance loan fee\b",
                r"\bguaranteed loan approval\b",
                r"\binstant loan.*fee\b",
                r"\bloan release charge\b",
            ],
            "signal": "loan_fee_scam",
            "description": "Possible advance-fee loan scam detected.",
        },

        "sextortion_or_blackmail": {
            "patterns": [
                r"\bpay or i will expose\b",
                r"\bshare your private photos\b",
                r"\bintimate video\b",
                r"\bblackmail\b",
                r"\bprivate pictures\b",
                r"\bexpose your photos\b",
                r"\bviral your video\b",
            ],
            "signal": "sextortion_or_blackmail",
            "description": "Possible blackmail or extortion language detected.",
        },

        "account_takeover": {
            "patterns": [
                r"\bverify your account immediately\b",
                r"\baccount suspended\b",
                r"\baccount deactivated\b",
                r"\breset your banking password\b",
                r"\bconfirm your login details\b",
                r"\bunauthorized login.*verify\b",
            ],
            "signal": "account_takeover",
            "description": "Possible account takeover tactic detected.",
        },

        "fake_customer_support": {
            "patterns": [
                r"\bcustomer care number\b",
                r"\brefund department\b",
                r"\bcall this support number\b",
                r"\bremote support for refund\b",
                r"\bamazon support\b",
                r"\bbank customer support\b",
            ],
            "signal": "fake_customer_support",
            "description": "Potential fake customer support indicator detected.",
        },

        "fake_bank_verification": {
            "patterns": [
                r"\bverify your bank account\b",
                r"\bconfirm your bank details\b",
                r"\bbank kyc expired\b",
                r"\bupdate bank kyc immediately\b",
            ],
            "signal": "fake_bank_verification",
            "description": "Possible fake bank verification detected.",
        },

        "card_cvv_request": {
            "patterns": [
                r"\bshare your cvv\b",
                r"\bprovide your cvv\b",
                r"\bsend your card pin\b",
                r"\bshare your card pin\b",
            ],
            "signal": "cvv_request",
            "description": "Sensitive card credential request detected.",
        },

        "investment_withdrawal_fee": {
            "patterns": [
                r"\bpay withdrawal fee\b",
                r"\bwithdrawal tax required\b",
                r"\bpay fee to withdraw\b",
                r"\bunlock investment profit\b",
            ],
            "signal": "investment_withdrawal_fee",
            "description": "Possible investment withdrawal fee scam detected.",
        },

        "fake_social_profile": {
            "patterns": [
                r"\bfake instagram profile\b",
                r"\bimpersonation account\b",
                r"\bfake facebook account\b",
                r"\bpretending to be someone\b",
            ],
            "signal": "fake_social_media_profile",
            "description": "Possible fake social media profile detected.",
        },

        "fake_delivery": {
            "patterns": [
                r"\bpay parcel delivery charge\b",
                r"\bdelivery fee required\b",
                r"\bparcel held.*payment\b",
                r"\bpay to release parcel\b",
            ],
            "signal": "fake_delivery_message",
            "description": "Possible fake delivery payment request detected.",
        },

        "email_spoofing": {
            "patterns": [
                r"\bemail spoofing\b",
                r"\bsuspicious reply-to\b",
                r"\bsender address mismatch\b",
                r"\bimpersonating.*email\b",
            ],
            "signal": "email_spoofing",
            "description": "Possible email sender impersonation detected.",
        },
    }

    # =====================================================
    # LEGACY CATEGORY CLASSIFICATION
    # =====================================================

    CATEGORY_PATTERNS = {

        "digitalArrest": [
            r"\bdigital arrest\b",
            r"\bpolice officer\b",
            r"\bcbi officer\b",
            r"\bcustoms department\b",
            r"\bvideo call.*arrest\b",
            r"\bvirtual arrest\b",
            r"\bcase registered against you\b",
        ],

        "investment": [
            r"\binvestment\b",
            r"\bguaranteed returns\b",
            r"\btrading profit\b",
            r"\bdouble your money\b",
            r"\bstock tips\b",
            r"\bcrypto investment\b",
            r"\btrading signals\b",
            r"\bportfolio management\b",
        ],

        "creditCard": [
            r"\bcredit card\b",
            r"\bcard details\b",
            r"\bcard limit\b",
            r"\bcard blocked\b",
            r"\bcvv\b",
            r"\bdebit card\b",
        ],

        "sextortion": [
            r"\bsextortion\b",
            r"\bprivate photos\b",
            r"\bintimate video\b",
            r"\bblackmail.*video\b",
            r"\bshare your private video\b",
            r"\bexpose your photos\b",
        ],

        "ecommerce": [
            r"\bparcel\b",
            r"\bdelivery charge\b",
            r"\border refund\b",
            r"\bonline shopping\b",
            r"\bproduct delivery\b",
            r"\bfake seller\b",
            r"\bpayment before delivery\b",
        ],

        "upiFraud": [
            r"\bupi\b",
            r"\bcollect request\b",
            r"\bscan qr\b",
            r"\bupi pin\b",
            r"\bpayment request\b",
        ],

        "jobScam": [
            r"\bjob offer\b",
            r"\bwork from home\b",
            r"\bjob registration\b",
            r"\bjob placement\b",
            r"\brecruitment fee\b",
        ],

        "loanScam": [
            r"\bloan\b",
            r"\bloan approval\b",
            r"\bloan processing\b",
            r"\binstant loan\b",
            r"\bloan release\b",
        ],

        "phishing": [
            r"\bphishing\b",
            r"\bverify your account\b",
            r"\bclick this link\b",
            r"\baccount suspended\b",
            r"\bpassword verification\b",
            r"\bunknown login link\b",
        ],

        "bankingFraud": [
            r"\bbank account\b",
            r"\bnet banking\b",
            r"\bbanking password\b",
            r"\baccount blocked\b",
            r"\bbank verification\b",
        ],

        "socialMediaScam": [
            r"\bfake profile\b",
            r"\binstagram giveaway\b",
            r"\bsocial media account\b",
            r"\bimpersonation account\b",
            r"\bfollower giveaway\b",
        ],

        "lotteryScam": [
            r"\blottery\b",
            r"\byou have won\b",
            r"\bprize money\b",
            r"\bclaim your reward\b",
            r"\bwinning amount\b",
        ],

        "romanceScam": [
            r"\bonline dating\b",
            r"\bromantic relationship\b",
            r"\bsend money.*love\b",
            r"\bemergency.*relationship\b",
            r"\bmarriage proposal\b",
        ],

        "fakeSupport": [
            r"\bcustomer care\b",
            r"\bcustomer support\b",
            r"\brefund department\b",
            r"\btechnical support\b",
            r"\bhelpdesk\b",
        ],

        "identityTheft": [
            r"\baadhaar\b",
            r"\bpan card\b",
            r"\bidentity proof\b",
            r"\bpersonal identity\b",
            r"\bidentity document\b",
        ],
    }

    # =====================================================
    # PRIVACY CONFIGURATION
    # =====================================================

    SENSITIVE_KEYWORDS = {
        "phone",
        "mobile",
        "email",
        "upi",
        "account",
        "card",
        "cvv",
        "pin",
        "password",
        "passwd",
        "otp",
        "token",
        "secret",
        "credential",
        "authorization",
        "session",
        "cookie",
        "private_key",
        "aadhaar",
        "pan",
    }

    # =====================================================
    # INITIALIZATION
    # =====================================================

    def __init__(self):

        self.preprocessor = TextPreprocessor()
        self.extractor = EvidenceExtractor()
        self.risk_scorer = RiskScorer()

        self.model = None
        self.model_metadata = {}

        self.model = self._load_model()

        logger.info(
            "FraudDetector initialized | version=%s | ML available=%s",
            self.VERSION,
            self.model is not None,
        )

    # =====================================================
    # OPTIONAL ML MODEL
    # =====================================================

    def _load_model(self):

        if not self.MODEL_PATH.exists():

            logger.warning(
                "Trained ML model not found. "
                "Rule-based detection will remain available."
            )

            return None

        try:

            artifact = joblib.load(self.MODEL_PATH)

            if isinstance(artifact, dict):

                model = artifact.get("pipeline")
                metadata = artifact.get("metadata", {})

                self.model_metadata = (
                    metadata if isinstance(metadata, dict) else {}
                )

            else:

                model = artifact

                self.model_metadata = {
                    "artifact_format": "legacy"
                }

            if (
                model is None
                or not callable(getattr(model, "predict", None))
            ):

                logger.error(
                    "Invalid ML model artifact: predict() unavailable."
                )

                return None

            logger.info("ML model loaded successfully.")

            return model

        except Exception:

            logger.exception("Could not load ML model.")

            self.model_metadata = {}

            return None

    # =====================================================
    # CONTEXT HELPERS
    # =====================================================

    def _is_victim_reported(self, text):

        return any(
            re.search(pattern, text, re.IGNORECASE)
            for pattern in self.VICTIM_REPORT_PATTERNS
        )

    def _is_educational_context(self, text):

        return any(
            re.search(pattern, text, re.IGNORECASE)
            for pattern in self.EDUCATIONAL_PATTERNS
        )

    def _is_advisory_context(self, text):

        return any(
            re.search(pattern, text, re.IGNORECASE)
            for pattern in self.ADVISORY_PATTERNS
        )

    def _is_actionable_match(self, text, match):
        """
        Evaluates context around an individual detection match.

        Victim reports are recognized locally.
        Educational examples are suppressed.
        Advisory instructions are not treated as scam requests.
        """

        start = max(0, match.start() - 160)
        end = min(len(text), match.end() + 100)

        local_context = text[start:end]

        if self._is_victim_reported(local_context):
            return True

        if self._is_educational_context(text):
            return False

        preceding_text = text[
            max(0, match.start() - 100):match.start()
        ].lower()

        advisory_patterns = [
            r"\bnever\s+$",
            r"\bdo not\s+$",
            r"\bdon't\s+$",
            r"\bshould not\s+$",
            r"\bmust not\s+$",
            r"\bavoid\s+$",
        ]

        if any(
            re.search(pattern, preceding_text)
            for pattern in advisory_patterns
        ):
            return False

        return True

    def _filter_context_matches(self, text, patterns):

        matched = []

        for pattern in patterns:

            try:

                for match in re.finditer(
                    pattern,
                    text,
                    re.IGNORECASE,
                ):

                    if self._is_actionable_match(text, match):
                        matched.append(pattern)
                        break

            except re.error:

                logger.warning(
                    "Invalid detection regex ignored: %s",
                    pattern,
                )

        return list(dict.fromkeys(matched))

    # =====================================================
    # INPUT VALIDATION
    # =====================================================

    def _validate_evidence_type(self, evidence_type):

        if not isinstance(evidence_type, str):

            raise ValueError(
                "Evidence type must be a string."
            )

        evidence_type = evidence_type.strip().lower()

        if evidence_type not in self.SUPPORTED_EVIDENCE_TYPES:

            raise ValueError(
                "Unsupported evidence type: " + evidence_type
            )

        return evidence_type

    # =====================================================
    # TEXT PREPROCESSING
    # =====================================================

    def _preprocess(self, evidence):

        methods = [
            "preprocess_text",
            "process_evidence",
            "process",
            "clean_text",
        ]

        for method_name in methods:

            method = getattr(
                self.preprocessor,
                method_name,
                None,
            )

            if not callable(method):
                continue

            try:

                result = method(evidence)

                if isinstance(result, dict):

                    processed = (
                        result.get("processed_text")
                        or result.get("text")
                    )

                    if isinstance(processed, str):
                        return processed

                elif isinstance(result, str):

                    return result

            except Exception:

                logger.exception(
                    "Preprocessing method failed: %s",
                    method_name,
                )

        logger.warning(
            "Preprocessing unavailable. Using normalized original text."
        )

        return evidence.lower()

    # =====================================================
    # URL EXTRACTION
    # =====================================================

    def _extract_urls(self, evidence):

        urls = []

        for match in self.URL_PATTERN.findall(evidence):

            candidate = match.rstrip(
                ".,!?;:)]}\"'"
            )

            if candidate.lower().startswith("www."):
                candidate = "http://" + candidate

            if candidate not in urls:
                urls.append(candidate)

        return urls

    # =====================================================
    # DOMAIN ANALYSIS
    # =====================================================

    def _analyze_domain(self, raw_url):

        result = {
            "domain": None,
            "is_shortened": False,
            "is_ip_address": False,
            "is_punycode": False,
            "brand_impersonation": False,
            "suspicious_keywords": [],
        }

        try:

            parsed = urlparse(raw_url)

            hostname = (
                parsed.hostname or ""
            ).lower().strip(".")

            if not hostname:
                return result

            result["domain"] = hostname

            if hostname in self.SHORTENED_DOMAINS:
                result["is_shortened"] = True

            try:

                ipaddress.ip_address(hostname)

                result["is_ip_address"] = True

            except ValueError:
                pass

            if any(
                label.startswith("xn--")
                for label in hostname.split(".")
            ):
                result["is_punycode"] = True

            labels = hostname.split(".")

            for brand in self.PROTECTED_BRANDS:

                for label in labels:

                    if label == brand:
                        continue

                    if (
                        brand in label
                        and len(label) > len(brand)
                    ):

                        result["brand_impersonation"] = True
                        break

                if result["brand_impersonation"]:
                    break

            result["suspicious_keywords"] = [
                keyword
                for keyword in self.SUSPICIOUS_DOMAIN_KEYWORDS
                if keyword in labels[:-1]
            ]

            return result

        except Exception:

            logger.exception("Domain analysis failed.")

            return result

    # =====================================================
    # URL AND PHISHING SIGNALS
    # =====================================================

    def _get_url_signals(self, evidence, evidence_type):

        signals = []

        urls = self._extract_urls(evidence)

        context_matches = self._filter_context_matches(
            evidence,
            self.URL_CONTEXT_PATTERNS,
        )

        credential_matches = self._filter_context_matches(
            evidence,
            self.CREDENTIAL_PATTERNS,
        )

        context_detected = bool(context_matches)
        credential_detected = bool(credential_matches)

        suspicious_domain_detected = False

        for raw_url in urls:

            domain_info = self._analyze_domain(raw_url)

            if domain_info["is_shortened"]:
                signals.append("shortened_url_detected")

            if domain_info["is_ip_address"]:
                signals.append("suspicious_domain")
                suspicious_domain_detected = True

            if domain_info["is_punycode"]:
                signals.append("suspicious_domain")
                suspicious_domain_detected = True

            if domain_info["brand_impersonation"]:
                signals.append("domain_impersonation")
                suspicious_domain_detected = True

            if (
                domain_info["suspicious_keywords"]
                and context_detected
            ):
                signals.append("suspicious_domain")
                suspicious_domain_detected = True

        if urls and context_detected:

            signals.append("suspicious_link")

            if credential_detected:

                signals.append("credential_harvesting")
                signals.append("phishing_url_detected")

            elif suspicious_domain_detected:

                signals.append("phishing_url_detected")

        if (
            evidence_type == "url"
            and context_detected
            and credential_detected
        ):

            signals.append("credential_harvesting")

        return list(dict.fromkeys(signals))

    # =====================================================
    # RULE DETECTION
    # =====================================================

    def _detect_rules(self, text):

        detected_rules = []
        signals = []

        for rule_name, rule_data in self.RULES.items():

            matched_patterns = self._filter_context_matches(
                text,
                rule_data["patterns"],
            )

            if not matched_patterns:
                continue

            detected_rules.append({
                "rule": rule_name,
                "description": rule_data["description"],
                "matched_patterns": matched_patterns[:3],
            })

            signals.append(rule_data["signal"])

        return detected_rules, list(dict.fromkeys(signals))

    # =====================================================
    # CATEGORY CLASSIFICATION
    # =====================================================

    def _classify_fraud_categories(self, text):

        detected_categories = []

        for category_id, category_data in self.FRAUD_CATEGORIES.items():

            matched_patterns = self._filter_context_matches(
                text,
                category_data["patterns"],
            )

            if not matched_patterns:
                continue

            detected_categories.append({
                "category": category_id,
                "name": category_data["name"],
                "matched_patterns": matched_patterns[:3],
            })

        return detected_categories

    # =====================================================
    # PRIMARY CATEGORY SELECTION
    # =====================================================

    def _select_primary_category(self, detected_categories):

        if not detected_categories:
            return "unknown"

        priority_map = {
            category: index
            for index, category in enumerate(
                self.CATEGORY_PRIORITY
            )
        }

        sorted_categories = sorted(
            detected_categories,
            key=lambda item: priority_map.get(
                item["category"],
                len(priority_map),
            ),
        )

        return sorted_categories[0]["category"]

    # =====================================================
    # LEGACY CATEGORY CLASSIFICATION
    # =====================================================

    def _classify_category(self, text):

        matches = []

        for category, patterns in self.CATEGORY_PATTERNS.items():

            matched = self._filter_context_matches(
                text,
                patterns,
            )

            if matched:
                matches.append(category)

        return matches if matches else ["unknown"]

    # =====================================================
    # EVIDENCE-TYPE SIGNALS
    # =====================================================

    def _get_evidence_type_signals(
        self,
        evidence,
        evidence_type,
    ):

        signals = []

        if evidence_type == "transaction":

            if re.search(
                r"\b(upi|imps|neft|rtgs|wallet|bank transfer)\b",
                evidence,
                re.IGNORECASE,
            ):

                signals.append(
                    "financial_transaction_reference"
                )

            credential_matches = self._filter_context_matches(
                evidence,
                self.CREDENTIAL_PATTERNS,
            )

            if credential_matches:

                signals.append(
                    "sensitive_financial_information"
                )

        elif evidence_type == "call":

            if re.search(
                r"\b(calling|call recording|voice call|video call)\b",
                evidence,
                re.IGNORECASE,
            ):

                signals.append("call_related_evidence")

        elif evidence_type == "email":

            email_header_pattern = (
                r"(?<!\w)(?:"
                r"from\s*:|"
                r"to\s*:|"
                r"cc\s*:|"
                r"bcc\s*:|"
                r"reply-to\s*:|"
                r"subject\s*:|"
                r"dear\s+customer\b"
                r")"
            )

            if re.search(
                email_header_pattern,
                evidence,
                re.IGNORECASE,
            ):

                signals.append(
                    "email_header_or_template_detected"
                )

        return list(dict.fromkeys(signals))

    # =====================================================
    # EVIDENCE EXTRACTION
    # =====================================================

    def _extract_indicators(self, evidence):

        try:

            extracted = self.extractor.extract(evidence)

            if not isinstance(extracted, dict):
                return {}

            indicators = extracted.get(
                "indicators",
                extracted,
            )

            return (
                indicators
                if isinstance(indicators, dict)
                else {}
            )

        except Exception:

            logger.exception(
                "Evidence extraction failed. "
                "Continuing with rule-based detection."
            )

            return {}

    # =====================================================
    # INDICATOR PRIVACY SANITIZATION
    # =====================================================

    def _is_sensitive_key(self, key):

        normalized = (
            str(key)
            .lower()
            .replace("-", "_")
            .strip("_")
        )

        container_suffixes = (
            "_details",
            "_information",
            "_info",
            "_data",
            "_metadata",
            "_records",
            "_history",
        )

        if normalized.endswith(container_suffixes):
            return False

        return any(
            keyword in normalized
            for keyword in self.SENSITIVE_KEYWORDS
        )

    def _sanitize_value(self, value, key=""):

        if self._is_sensitive_key(key):
            return "[REDACTED]"

        if isinstance(value, dict):

            sanitized = {}

            for child_key, child_value in value.items():

                sanitized[child_key] = self._sanitize_value(
                    child_value,
                    str(child_key),
                )

            return sanitized

        if isinstance(value, list):

            return [
                self._sanitize_value(item, key)
                for item in value
            ]

        if isinstance(value, tuple):

            return [
                self._sanitize_value(item, key)
                for item in value
            ]

        if isinstance(value, str):

            value = re.sub(
                r"(?<!\w)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\w)",
                "[REDACTED_PHONE]",
                value,
            )

            value = re.sub(
                r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
                "[REDACTED_EMAIL]",
                value,
                flags=re.IGNORECASE,
            )

            value = re.sub(
                r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)",
                "[REDACTED_ID]",
                value,
            )

            return value

        return value

    def _sanitize_indicators(self, indicators):

        if not isinstance(indicators, dict):
            return {}

        return self._sanitize_value(indicators)

    # =====================================================
    # OPTIONAL ML PREDICTION
    # =====================================================

    def _predict_ml(self, text):

        unavailable = {
            "available": False,
            "prediction": None,
            "confidence": None,
            "method": "not_available",
            "metadata": {},
        }

        if self.model is None:
            return unavailable

        try:

            predictions = self.model.predict([text])

            if predictions is None or len(predictions) == 0:
                raise ValueError("Empty ML prediction.")

            prediction = predictions[0]

            if prediction is None:
                raise ValueError("Invalid ML prediction.")

            confidence = None

            predict_proba = getattr(
                self.model,
                "predict_proba",
                None,
            )

            if callable(predict_proba):

                probabilities = predict_proba([text])

                if probabilities is not None and len(probabilities) > 0:

                    probability_row = probabilities[0]

                    values = [
                        float(value)
                        for value in probability_row
                    ]

                    if not values:
                        raise ValueError(
                            "Empty probability output."
                        )

                    if not all(
                        math.isfinite(value)
                        and 0 <= value <= 1
                        for value in values
                    ):

                        raise ValueError(
                            "Invalid ML probability values."
                        )

                    confidence = round(max(values), 4)

            return {
                "available": True,
                "prediction": str(prediction),
                "confidence": confidence,
                "method": "tfidf_logistic_regression",
                "metadata": {
                    "model_version": self.model_metadata.get(
                        "model_version"
                    ),
                    "advisory_only": True,
                    "production_ready": self.model_metadata.get(
                        "production_ready",
                        False,
                    ),
                },
                "confidence_note": (
                    "Model confidence is not necessarily "
                    "a calibrated fraud probability."
                ),
            }

        except Exception:

            logger.exception(
                "ML prediction failed. "
                "Continuing without ML advisory."
            )

            return {
                "available": False,
                "prediction": None,
                "confidence": None,
                "method": "prediction_error",
                "metadata": {},
            }

    # =====================================================
    # RISK SCORING
    # =====================================================

    def _calculate_risk(
        self,
        signals,
        indicators,
        categories=None,
    ):

        unique_signals = list(dict.fromkeys(signals))
        unique_categories = list(dict.fromkeys(categories or []))

        calculate_method = getattr(
            self.risk_scorer,
            "calculate",
            None,
        )

        if callable(calculate_method):

            result = calculate_method(
                signals=unique_signals,
                indicators=indicators,
                base_score=0,
                categories=unique_categories,
            )

        else:

            calculate_signal_score = getattr(
                self.risk_scorer,
                "calculate_signal_score",
                None,
            )

            if not callable(calculate_signal_score):

                raise RuntimeError(
                    "RiskScorer has no compatible scoring method."
                )

            score_result = calculate_signal_score(
                unique_signals
            )

            if (
                isinstance(score_result, tuple)
                and len(score_result) == 2
            ):

                score, breakdown = score_result

            elif isinstance(score_result, dict):

                score = score_result.get("risk_score", 0)
                breakdown = score_result.get("breakdown", {})

            else:

                raise RuntimeError(
                    "Unsupported RiskScorer response."
                )

            risk_score = float(score)

            if hasattr(self.risk_scorer, "get_risk_level"):

                risk_level = self.risk_scorer.get_risk_level(
                    risk_score
                )

            else:

                risk_level = self._get_fallback_risk_level(
                    risk_score
                )

            result = {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "recommendations": [],
                "breakdown": breakdown,
            }

        if not isinstance(result, dict):

            raise RuntimeError(
                "Invalid risk scorer response."
            )

        required_keys = [
            "risk_score",
            "risk_level",
            "recommendations",
            "breakdown",
        ]

        missing = [
            key for key in required_keys
            if key not in result
        ]

        if missing:

            raise RuntimeError(
                "Risk scorer response missing: "
                + ", ".join(missing)
            )

        try:

            risk_score = float(result["risk_score"])

        except (TypeError, ValueError):

            raise RuntimeError(
                "RiskScorer returned an invalid risk score."
            )

        if (
            not math.isfinite(risk_score)
            or not 0 <= risk_score <= 100
        ):

            raise RuntimeError(
                "Risk score must be finite and between 0 and 100."
            )

        result["risk_score"] = risk_score

        return result

    @staticmethod
    def _get_fallback_risk_level(score):

        if score <= 24:
            return "LOW"

        if score <= 49:
            return "MEDIUM"

        if score <= 74:
            return "HIGH"

        return "CRITICAL"

    # =====================================================
    # EXPLANATIONS
    # =====================================================

    def _build_explanations(
        self,
        detected_rules,
        detected_categories,
        evidence_signals,
    ):

        explanations = []

        for rule in detected_rules:

            explanations.append(
                rule["description"]
            )

        for category in detected_categories:

            explanations.append(
                category["name"] + " indicators detected."
            )

        if evidence_signals:

            explanations.append(
                "Evidence-type-specific indicators were identified."
            )

        if not explanations:

            explanations.append(
                "No configured scam rules matched this evidence."
            )

        return list(dict.fromkeys(explanations))

    # =====================================================
    # MAIN ANALYSIS
    # =====================================================

    def analyze(
        self,
        evidence,
        evidence_type="message",
    ):

        if not isinstance(evidence, str):

            raise ValueError(
                "Evidence must be a string."
            )

        evidence = evidence.strip()

        if not evidence:

            raise ValueError(
                "Evidence cannot be empty."
            )

        if len(evidence) > self.MAX_EVIDENCE_LENGTH:

            raise ValueError(
                "Evidence exceeds maximum length."
            )

        evidence_type = self._validate_evidence_type(
            evidence_type
        )

        # Text preprocessing.
        processed_text = self._preprocess(evidence)

        if not isinstance(processed_text, str):
            processed_text = evidence.lower()

        processed_text = processed_text.lower()

        analysis_text = (
            evidence.lower()
            + "\n"
            + processed_text
        )

        # Rule detection.
        detected_rules, rule_signals = self._detect_rules(
            analysis_text
        )

        # Evidence-type signals.
        evidence_signals = self._get_evidence_type_signals(
            evidence,
            evidence_type,
        )

        # URL signals.
        url_signals = self._get_url_signals(
            evidence,
            evidence_type,
        )

        signals = list(
            dict.fromkeys(
                rule_signals
                + evidence_signals
                + url_signals
            )
        )

        # Fraud category classification.
        detected_categories = self._classify_fraud_categories(
            analysis_text
        )

        phishing_support = {
            "suspicious_link",
            "domain_impersonation",
            "credential_harvesting",
            "phishing_url_detected",
        }

        if (
            phishing_support.intersection(signals)
            and not any(
                item["category"] == "url_phishing"
                for item in detected_categories
            )
        ):

            detected_categories.append({
                "category": "url_phishing",
                "name": self.FRAUD_CATEGORIES[
                    "url_phishing"
                ]["name"],
                "matched_patterns": [
                    "heuristic_url_analysis"
                ],
            })

        fraud_categories = [
            item["category"]
            for item in detected_categories
        ]

        primary_category = self._select_primary_category(
            detected_categories
        )

        # Evidence extraction.
        indicators = self._extract_indicators(
            evidence
        )

        safe_indicators = self._sanitize_indicators(
            indicators
        )

        # Risk scoring.
        risk_result = self._calculate_risk(
            signals=signals,
            indicators=indicators,
            categories=fraud_categories,
        )

        # Legacy classification.
        legacy_categories = self._classify_category(
            analysis_text
        )

        # Optional ML prediction.
        ml_result = self._predict_ml(
            processed_text
        )

        # Explanations.
        explanations = self._build_explanations(
            detected_rules,
            detected_categories,
            evidence_signals + url_signals,
        )

        # Final response.
        return {
            "success": True,

            "detector_version": self.VERSION,

            "evidence_type": evidence_type,

            "fraud_category": primary_category,

            "fraud_categories": fraud_categories,

            "category_details": detected_categories,

            "legacy_categories": legacy_categories,

            "risk_score": risk_result["risk_score"],

            "risk_level": risk_result["risk_level"],

            "signals": signals,

            "detected_rules": detected_rules,

            "indicators": safe_indicators,

            "explanations": explanations,

            "recommendations": risk_result["recommendations"],

            "scoring": risk_result["breakdown"],

            "machine_learning": ml_result,

            "analysis_method": (
                "rules_with_ml_advisory"
                if ml_result["available"]
                else "rule_based"
            ),

            "verification": {
                "status": "UNVERIFIED",
                "external_verification": False,
            },

            "disclaimer": (
                "This result is an AI-generated risk assessment. "
                "It is not proof of fraud or legitimacy. "
                "Risk scores are heuristic, not calibrated probabilities. "
                "URL analysis is heuristic and does not perform live "
                "domain reputation verification. "
                "Call evidence requires supplied transcript or text. "
                "Screenshot evidence requires supplied extracted text. "
                "Verify suspicious claims through official channels."
            ),
        }


# =========================================================
# SHARED DETECTOR INSTANCE
# =========================================================

fraud_detector = FraudDetector()


# =========================================================
# CONVENIENCE FUNCTION
# =========================================================

def analyze_evidence(
    evidence,
    evidence_type="message",
):

    return fraud_detector.analyze(
        evidence=evidence,
        evidence_type=evidence_type,
    )