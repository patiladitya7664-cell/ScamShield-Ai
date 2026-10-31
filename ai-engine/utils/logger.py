
"""
====================================================
SCAMSHIELD AI - CENTRALIZED LOGGING SYSTEM
====================================================
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


# =====================================================
# DIRECTORIES
# =====================================================

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"

LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "scamshield.log"


# =====================================================
# LOGGER FACTORY
# =====================================================

def create_logger(name: str = "ScamShieldAI") -> logging.Logger:

    agent_logger = logging.getLogger(name)

    if agent_logger.handlers:
        return agent_logger

    agent_logger.setLevel(logging.INFO)
    agent_logger.propagate = False

    formatter = logging.Formatter(
        fmt=(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(name)s | "
            "%(message)s"
        ),
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )

    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    agent_logger.addHandler(console_handler)
    agent_logger.addHandler(file_handler)

    return agent_logger


# =====================================================
# APPLICATION LOGGERS
# =====================================================

logger = create_logger("ScamShieldAI")

guardian_logger = create_logger("GuardianAgent")

intelligence_logger = create_logger("IntelligenceAgent")

victim_safety_logger = create_logger("VictimSafetyAgent")

decoy_logger = create_logger("DecoyAgent")

orchestrator_logger = create_logger("AgentOrchestrator")


# =====================================================
# STANDARD AGENT EXECUTION LOGGER
# =====================================================

def log_agent_execution(
    agent_name: str,
    status: str,
    message: str = "",
) -> None:
    """
    Standard execution logger.

    Supported statuses:
        SUCCESS
        COMPLETED
        WARNING
        ERROR
        FAILED

    Do not pass raw evidence or sensitive information.
    """

    agent_logger = create_logger(agent_name)

    normalized_status = str(status).strip().upper()

    safe_message = str(message)[:1000]

    if normalized_status in {"SUCCESS", "COMPLETED"}:

        agent_logger.info(
            "Execution successful | %s",
            safe_message,
        )

    elif normalized_status == "WARNING":

        agent_logger.warning(
            "Execution warning | %s",
            safe_message,
        )

    elif normalized_status in {"ERROR", "FAILED"}:

        agent_logger.error(
            "Execution failed | %s",
            safe_message,
        )

    else:

        agent_logger.info(
            "Execution status: %s | %s",
            normalized_status,
            safe_message,
        )


# =====================================================
# EXCEPTION LOGGER
# =====================================================

def log_exception(
    message: str,
    exception: Exception,
) -> None:

    logger.error(
        "%s | Exception: %s",
        message,
        type(exception).__name__,
        exc_info=(
            type(exception),
            exception,
            exception.__traceback__,
        ),
    )
