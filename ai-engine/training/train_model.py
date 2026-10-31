
"""
=========================================================
SCAMSHIELD AI - MODEL TRAINING
=========================================================

Training approach:
    1. Load and validate dataset.
    2. Normalize text and labels.
    3. Split training and testing data.
    4. Convert text into TF-IDF features.
    5. Train Logistic Regression classifier.
    6. Evaluate model.
    7. Save model and training metrics.

Expected dataset:
    ai-engine/dataset/scam_dataset.csv

Expected columns:
    text, label

Expected labels:
    scam
    legitimate

Saved model:
    ai-engine/models/fraud_model.joblib

IMPORTANT:
    This model is advisory only.
    A small starter dataset cannot establish
    production-grade fraud detection performance.
=========================================================
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)


# =========================================================
# PATH CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parents[1]

DATASET_PATH = BASE_DIR / "dataset" / "scam_dataset.csv"

MODEL_DIR = BASE_DIR / "models"

MODEL_PATH = MODEL_DIR / "fraud_model.joblib"

METRICS_PATH = MODEL_DIR / "training_metrics.json"


# =========================================================
# TRAINING CONFIGURATION
# =========================================================

RANDOM_STATE = 42

TEST_SIZE = 0.20

MINIMUM_SAMPLES = 10

EXPECTED_LABELS = {
    "scam",
    "legitimate",
}


# =========================================================
# LOGGING
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("ScamShield-Training")


# =========================================================
# DATASET COLUMN CONFIGURATION
# =========================================================

TEXT_COLUMN_CANDIDATES = [
    "text",
    "message",
    "content",
    "sms",
    "email",
    "description",
    "evidence",
]

LABEL_COLUMN_CANDIDATES = [
    "label",
    "target",
    "class",
    "category",
    "is_scam",
    "is_fraud",
]


# =========================================================
# DATASET LOADER
# =========================================================


def load_dataset():

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    logger.info("Loading training dataset...")

    dataframe = pd.read_csv(DATASET_PATH)

    if dataframe.empty:
        raise ValueError("Dataset is empty.")

    dataframe.columns = [
        str(column).strip().lower()
        for column in dataframe.columns
    ]

    if len(dataframe.columns) != len(set(dataframe.columns)):
        raise ValueError(
            "Dataset contains duplicate column names."
        )

    text_column = next(
        (
            column
            for column in TEXT_COLUMN_CANDIDATES
            if column in dataframe.columns
        ),
        None,
    )

    label_column = next(
        (
            column
            for column in LABEL_COLUMN_CANDIDATES
            if column in dataframe.columns
        ),
        None,
    )

    if text_column is None or label_column is None:
        raise ValueError(
            "Dataset must contain a valid text column "
            "and a valid label column. "
            f"Available columns: {list(dataframe.columns)}"
        )

    dataframe = dataframe[
        [text_column, label_column]
    ].copy()

    dataframe.columns = [
        "text",
        "label",
    ]

    dataframe["text"] = (
        dataframe["text"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    dataframe["label"] = (
        dataframe["label"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )

    dataframe = dataframe[
        (dataframe["text"] != "")
        & (dataframe["label"] != "")
    ]

    dataframe = dataframe.drop_duplicates(
        subset=["text", "label"]
    ).reset_index(drop=True)

    if len(dataframe) < MINIMUM_SAMPLES:
        raise ValueError(
            f"At least {MINIMUM_SAMPLES} valid samples "
            "are required for training."
        )

    unique_labels = set(
        dataframe["label"].unique()
    )

    if len(unique_labels) < 2:
        raise ValueError(
            "At least two different classes are required."
        )

    unexpected_labels = unique_labels - EXPECTED_LABELS

    if unexpected_labels:
        raise ValueError(
            "Unsupported dataset labels found: "
            f"{sorted(unexpected_labels)}. "
            f"Expected labels: {sorted(EXPECTED_LABELS)}"
        )

    class_counts = dataframe["label"].value_counts()

    if class_counts.min() < 2:
        raise ValueError(
            "Every class must contain at least two samples "
            "for a train/test split."
        )

    logger.info(
        "Dataset loaded successfully. Total samples: %s",
        len(dataframe),
    )

    logger.info(
        "Class distribution: %s",
        class_counts.to_dict(),
    )

    return dataframe


# =========================================================
# TRAIN / TEST SPLIT
# =========================================================


def split_dataset(dataframe):

    X = dataframe["text"]

    y = dataframe["label"]

    class_counts = y.value_counts()

    # Stratification is used only when every class
    # has enough samples for a meaningful split.

    test_sample_count = max(
        1,
        int(round(len(dataframe) * TEST_SIZE)),
    )

    train_sample_count = (
        len(dataframe) - test_sample_count
    )

    can_stratify = (
        class_counts.min() >= 2
        and test_sample_count >= len(class_counts)
        and train_sample_count >= len(class_counts)
    )

    stratify = y if can_stratify else None

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=stratify,
    )

    if y_train.nunique() < 2:
        raise ValueError(
            "Training split contains fewer than two classes."
        )

    logger.info(
        "Stratified split enabled: %s",
        can_stratify,
    )

    return (
        X_train,
        X_test,
        y_train,
        y_test,
    )


# =========================================================
# MODEL CREATION
# =========================================================


def create_model():

    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    strip_accents="unicode",
                    ngram_range=(1, 2),
                    max_features=20000,
                    sublinear_tf=True,
                    min_df=1,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=RANDOM_STATE,
                ),
            ),
        ]
    )


# =========================================================
# MODEL EVALUATION
# =========================================================


def evaluate_model(
    model,
    X_test,
    y_test,
):

    logger.info("Evaluating trained model...")

    predictions = model.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    report = classification_report(
        y_test,
        predictions,
        labels=model.classes_,
        output_dict=True,
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=model.classes_,
    )

    logger.info(
        "Test accuracy: %.4f",
        accuracy,
    )

    logger.info(
        "Classification report:\n%s",
        classification_report(
            y_test,
            predictions,
            labels=model.classes_,
            zero_division=0,
        ),
    )

    return {
        "accuracy": float(accuracy),
        "classification_report": report,
        "confusion_matrix": matrix.tolist(),
        "class_labels": model.classes_.tolist(),
        "test_samples": int(len(y_test)),
    }


# =========================================================
# SAVE MODEL AND METRICS
# =========================================================


def save_artifacts(
    model,
    metrics,
):

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    model_metadata = {
        "model_type": "TF-IDF + Logistic Regression",
        "model_version": "1.0.0",
        "trained_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "dataset_path": str(DATASET_PATH),
        "training_samples": metrics["training_samples"],
        "test_samples": metrics["test_samples"],
        "total_samples": metrics["total_samples"],
        "classes": metrics["class_labels"],
        "accuracy": metrics["accuracy"],
        "advisory_only": True,
    }

    artifact = {
        "pipeline": model,
        "metadata": model_metadata,
    }

    joblib.dump(
        artifact,
        MODEL_PATH,
    )

    with open(
        METRICS_PATH,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            metrics,
            file,
            indent=4,
            ensure_ascii=False,
        )

    logger.info(
        "Model saved: %s",
        MODEL_PATH,
    )

    logger.info(
        "Training metrics saved: %s",
        METRICS_PATH,
    )


# =========================================================
# MAIN TRAINING FUNCTION
# =========================================================


def train_model():

    logger.info(
        "========== SCAMSHIELD AI TRAINING STARTED =========="
    )

    dataframe = load_dataset()

    (
        X_train,
        X_test,
        y_train,
        y_test,
    ) = split_dataset(dataframe)

    logger.info(
        "Training samples: %s | Testing samples: %s",
        len(X_train),
        len(X_test),
    )

    model = create_model()

    logger.info(
        "Training TF-IDF + Logistic Regression..."
    )

    model.fit(
        X_train,
        y_train,
    )

    metrics = evaluate_model(
        model,
        X_test,
        y_test,
    )

    metrics.update(
        {
            "training_samples": int(len(X_train)),
            "total_samples": int(len(dataframe)),
            "model_type": "TF-IDF + Logistic Regression",
            "random_state": RANDOM_STATE,
            "test_size": TEST_SIZE,
            "training_timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "advisory_only": True,
            "production_ready": False,
            "dataset_warning": (
                "Performance on a small starter dataset "
                "does not establish real-world fraud detection accuracy."
            ),
        }
    )

    save_artifacts(
        model,
        metrics,
    )

    logger.info(
        "========== MODEL TRAINING COMPLETED =========="
    )

    return {
        "success": True,
        "model_path": str(MODEL_PATH),
        "metrics_path": str(METRICS_PATH),
        "accuracy": metrics["accuracy"],
        "total_samples": metrics["total_samples"],
        "advisory_only": True,
        "production_ready": False,
    }


# =========================================================
# SCRIPT ENTRY POINT
# =========================================================


if __name__ == "__main__":

    try:

        result = train_model()

        print("\nSCAMSHIELD AI TRAINING RESULT")
        print("-" * 45)

        print(
            json.dumps(
                result,
                indent=4,
            )
        )

    except Exception:

        logger.exception(
            "Model training failed."
        )

        raise
