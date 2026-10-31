
"""
=========================================================
SCAMSHIELD AI - MODEL EVALUATION
=========================================================

Responsibilities:
    1. Load the trained fraud detection artifact.
    2. Load and validate the dataset.
    3. Recreate the reproducible test split.
    4. Evaluate model predictions.
    5. Generate classification metrics.
    6. Save evaluation results.

Required files:
    dataset/scam_dataset.csv
    models/fraud_model.joblib

Output:
    models/evaluation_report.json

IMPORTANT:
    Evaluation metrics on a small dataset are not
    proof of real-world fraud detection performance.
=========================================================
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)


# =========================================================
# PATH CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parents[1]

DATASET_PATH = BASE_DIR / "dataset" / "scam_dataset.csv"

MODEL_PATH = BASE_DIR / "models" / "fraud_model.joblib"

REPORT_PATH = BASE_DIR / "models" / "evaluation_report.json"


# =========================================================
# EVALUATION CONFIGURATION
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

logger = logging.getLogger("ScamShield-Evaluation")


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
# LOAD DATASET
# =========================================================

def load_dataset():

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    logger.info("Loading evaluation dataset...")

    dataframe = pd.read_csv(DATASET_PATH)

    if dataframe.empty:
        raise ValueError(
            "Dataset is empty."
        )

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
            "Dataset must contain text and label columns. "
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
            "are required for evaluation."
        )

    unique_labels = set(
        dataframe["label"].unique()
    )

    if len(unique_labels) < 2:
        raise ValueError(
            "At least two classes are required."
        )

    unexpected_labels = unique_labels - EXPECTED_LABELS

    if unexpected_labels:
        raise ValueError(
            "Unsupported dataset labels found: "
            f"{sorted(unexpected_labels)}"
        )

    if dataframe["label"].value_counts().min() < 2:
        raise ValueError(
            "Every class must contain at least two samples."
        )

    logger.info(
        "Dataset loaded. Samples: %s",
        len(dataframe),
    )

    logger.info(
        "Class distribution: %s",
        dataframe["label"].value_counts().to_dict(),
    )

    return dataframe


# =========================================================
# LOAD TRAINED MODEL ARTIFACT
# =========================================================

def load_model():

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Trained model not found: {MODEL_PATH}. "
            "Train the model before evaluation."
        )

    logger.info("Loading trained model artifact...")

    artifact = joblib.load(MODEL_PATH)

    metadata = {}

    # Current artifact format:
    # {
    #     "pipeline": trained_pipeline,
    #     "metadata": {...}
    # }

    if isinstance(artifact, dict):

        model = artifact.get("pipeline")

        metadata = artifact.get("metadata", {})

        if model is None:
            raise ValueError(
                "Model artifact does not contain a pipeline."
            )

        if not isinstance(metadata, dict):
            metadata = {}

    else:
        # Backward compatibility with older artifacts
        # that directly stored the sklearn pipeline.

        model = artifact

    if not callable(getattr(model, "predict", None)):
        raise TypeError(
            "Loaded model does not support prediction."
        )

    if not hasattr(model, "classes_"):
        raise TypeError(
            "Loaded model does not expose trained classes."
        )

    logger.info(
        "Model loaded successfully."
    )

    return model, metadata


# =========================================================
# CREATE REPRODUCIBLE TEST DATASET
# =========================================================

def prepare_test_data(
    dataframe,
    model,
):

    X = dataframe["text"]

    y = dataframe["label"]

    model_classes = {
        str(label).strip().lower()
        for label in model.classes_
    }

    dataset_classes = set(
        y.unique()
    )

    if model_classes != dataset_classes:
        raise ValueError(
            "Dataset labels do not match trained model classes. "
            f"Model classes: {sorted(model_classes)}; "
            f"Dataset classes: {sorted(dataset_classes)}"
        )

    class_counts = y.value_counts()

    test_sample_count = max(
        1,
        int(round(len(dataframe) * TEST_SIZE)),
    )

    train_sample_count = (
        len(dataframe) - test_sample_count
    )

    # Keep the split logic identical to train_model.py.

    can_stratify = (
        class_counts.min() >= 2
        and test_sample_count >= len(class_counts)
        and train_sample_count >= len(class_counts)
    )

    stratify = y if can_stratify else None

    _, X_test, _, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=stratify,
    )

    logger.info(
        "Evaluation samples: %s",
        len(X_test),
    )

    logger.info(
        "Stratified split enabled: %s",
        can_stratify,
    )

    return X_test, y_test


# =========================================================
# EVALUATE MODEL
# =========================================================

def evaluate_model(
    model,
    X_test,
    y_test,
):

    logger.info(
        "Generating model predictions..."
    )

    predictions = model.predict(X_test)

    labels = [
        str(label)
        for label in model.classes_
    ]

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    precision = precision_score(
        y_test,
        predictions,
        labels=labels,
        average="weighted",
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        predictions,
        labels=labels,
        average="weighted",
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        predictions,
        labels=labels,
        average="weighted",
        zero_division=0,
    )

    report = classification_report(
        y_test,
        predictions,
        labels=labels,
        output_dict=True,
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=labels,
    )

    results = {
        "model_type": "TF-IDF + Logistic Regression",
        "evaluation_timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "test_samples": int(len(y_test)),
        "classes": labels,
        "metrics": {
            "accuracy": float(accuracy),
            "precision_weighted": float(precision),
            "recall_weighted": float(recall),
            "f1_weighted": float(f1),
        },
        "classification_report": report,
        "confusion_matrix": {
            "labels": labels,
            "matrix": matrix.tolist(),
        },
        "evaluation_note": (
            "Metrics are estimates on a held-out split. "
            "They do not guarantee real-world performance."
        ),
        "advisory_only": True,
        "production_ready": False,
    }

    return results


# =========================================================
# SAVE EVALUATION REPORT
# =========================================================

def save_report(results):

    REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        REPORT_PATH,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            results,
            file,
            indent=4,
            ensure_ascii=False,
        )

    logger.info(
        "Evaluation report saved: %s",
        REPORT_PATH,
    )


# =========================================================
# MAIN EVALUATION FUNCTION
# =========================================================

def run_evaluation():

    logger.info(
        "========== MODEL EVALUATION STARTED =========="
    )

    dataframe = load_dataset()

    model, model_metadata = load_model()

    X_test, y_test = prepare_test_data(
        dataframe,
        model,
    )

    results = evaluate_model(
        model,
        X_test,
        y_test,
    )

    results["model_metadata"] = model_metadata

    results["dataset_samples"] = int(
        len(dataframe)
    )

    results["random_state"] = RANDOM_STATE

    results["test_size"] = TEST_SIZE

    save_report(results)

    logger.info(
        "========== MODEL EVALUATION COMPLETED =========="
    )

    print(
        "\nSCAMSHIELD AI - EVALUATION RESULTS"
    )

    print("-" * 45)

    for metric, value in results["metrics"].items():
        print(
            f"{metric}: {value:.4f}"
        )

    print(
        f"\nReport: {REPORT_PATH}"
    )

    return results


# =========================================================
# SCRIPT ENTRY POINT
# =========================================================

if __name__ == "__main__":

    try:
        run_evaluation()

    except Exception:
        logger.exception(
            "Model evaluation failed."
        )

        raise
