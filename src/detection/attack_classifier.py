from __future__ import annotations

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    classification_report,
)
from sklearn.model_selection import train_test_split

from src.core.config import Config


class AttackClassifier:
    """
    Train and evaluate a Random Forest network-attack classifier.

    When source_file is available, the train/test split is performed by PCAP
    capture so windows from the same capture cannot appear in both sets.
    """

    def __init__(self) -> None:
        self.model = RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced_subsample",
            min_samples_leaf=2,
            n_jobs=-1,
            random_state=Config.RANDOM_STATE,
        )
        self.feature_columns = list(Config.FEATURE_COLUMNS)
        self.is_trained = False

    def _validate_dataset(self, df: pd.DataFrame) -> None:
        required = set(self.feature_columns + ["attack_type"])
        missing = required.difference(df.columns)
        if missing:
            raise ValueError(
                "Dataset is missing required columns: "
                + ", ".join(sorted(missing))
            )

        class_counts = df["attack_type"].value_counts()
        if len(class_counts) < 2:
            raise ValueError("At least two attack classes are required.")

        if (class_counts < 2).any():
            too_small = class_counts[class_counts < 2].to_dict()
            raise ValueError(
                f"Each class needs at least two rows. Too small: {too_small}"
            )

    def _capture_aware_split(
        self,
        df: pd.DataFrame,
        X: pd.DataFrame,
        y: pd.Series,
    ):
        """
        Hold out at least one complete capture per class.

        This avoids overly optimistic evaluation caused by putting windows
        from the same PCAP in both training and testing sets.
        """
        if "source_file" not in df.columns:
            return train_test_split(
                X,
                y,
                test_size=Config.TEST_SIZE,
                random_state=Config.RANDOM_STATE,
                stratify=y,
            )

        rng = np.random.RandomState(Config.RANDOM_STATE)
        test_files: set[str] = set()

        for label in sorted(y.unique()):
            class_files = (
                df.loc[y == label, "source_file"]
                .dropna()
                .astype(str)
                .unique()
            )

            if len(class_files) < 2:
                print(
                    f"[!] Class '{label}' has fewer than two captures. "
                    "Falling back to a stratified row split."
                )
                return train_test_split(
                    X,
                    y,
                    test_size=Config.TEST_SIZE,
                    random_state=Config.RANDOM_STATE,
                    stratify=y,
                )

            shuffled = class_files.copy()
            rng.shuffle(shuffled)
            number_to_test = max(
                1,
                int(round(len(shuffled) * Config.TEST_SIZE)),
            )
            test_files.update(shuffled[:number_to_test])

        test_mask = df["source_file"].astype(str).isin(test_files)

        if not test_mask.any() or test_mask.all():
            raise RuntimeError("Capture-aware split produced an invalid split.")

        return (
            X.loc[~test_mask],
            X.loc[test_mask],
            y.loc[~test_mask],
            y.loc[test_mask],
        )

    def train(self, df: pd.DataFrame) -> dict:
        """Train the model and write evaluation artefacts."""
        Config.ensure_directories()
        self._validate_dataset(df)

        X = (
            df[self.feature_columns]
            .apply(pd.to_numeric, errors="coerce")
            .fillna(0)
        )
        y = df["attack_type"].astype(str)

        X_train, X_test, y_train, y_test = self._capture_aware_split(
            df, X, y
        )

        print("\n[+] STARTING MODEL TRAINING")
        print(f"[+] Total rows: {len(df):,}")
        print(f"[+] Training rows: {len(X_train):,}")
        print(f"[+] Testing rows: {len(X_test):,}")
        print(f"[+] Features: {len(self.feature_columns)}")
        print("\n[+] Training class distribution:")
        print(y_train.value_counts())
        print("\n[+] Testing class distribution:")
        print(y_test.value_counts())

        self.model.fit(X_train, y_train)
        self.is_trained = True

        predictions = self.model.predict(X_test)
        labels = list(self.model.classes_)

        report_text = classification_report(
            y_test,
            predictions,
            labels=labels,
            zero_division=0,
        )
        print("\n=== CLASSIFICATION REPORT ===\n")
        print(report_text)
        Config.CLASSIFICATION_REPORT_PATH.write_text(
            report_text,
            encoding="utf-8",
        )

        # Save feature importance.
        importance_df = (
            pd.DataFrame(
                {
                    "feature": self.feature_columns,
                    "importance": self.model.feature_importances_,
                }
            )
            .sort_values("importance", ascending=False)
            .reset_index(drop=True)
        )
        importance_df.to_csv(
            Config.FEATURE_IMPORTANCE_PATH,
            index=False,
        )

        print("\n=== FEATURE IMPORTANCE ===\n")
        for row in importance_df.itertuples(index=False):
            print(f"{row.feature}: {row.importance:.4f}")

        # Save confusion matrix.
        figure, axis = plt.subplots(figsize=(8, 6))
        ConfusionMatrixDisplay.from_predictions(
            y_test,
            predictions,
            labels=labels,
            display_labels=labels,
            cmap="Blues",
            values_format="d",
            ax=axis,
        )
        axis.set_title("Attack Classification Confusion Matrix")
        figure.tight_layout()
        figure.savefig(Config.CONFUSION_MATRIX_PATH, dpi=160)
        plt.close(figure)

        return {
            "X_test": X_test,
            "y_test": y_test,
            "predictions": predictions,
            "classification_report": report_text,
            "feature_importance": importance_df,
        }

    def save(self) -> None:
        """Persist the trained estimator and exact feature schema."""
        if not self.is_trained:
            raise RuntimeError("Run train() before save().")

        Config.ensure_directories()
        joblib.dump(self.model, Config.MODEL_PATH)
        joblib.dump(self.feature_columns, Config.FEATURE_PATH)

        print("\n[+] MODEL ARTEFACTS SAVED")
        print(f"[+] Model: {Config.MODEL_PATH}")
        print(f"[+] Feature schema: {Config.FEATURE_PATH}")
        print(f"[+] Confusion matrix: {Config.CONFUSION_MATRIX_PATH}")
        print(f"[+] Feature importance: {Config.FEATURE_IMPORTANCE_PATH}")
