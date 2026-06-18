import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import joblib


class AttackClassifier:

    def __init__(self):

        self.model = RandomForestClassifier(
            n_estimators=100,
            random_state=42
        )

    def train(self, df):

        X = df.drop(
            columns=["src_ip", "attack_type"]
        )

        y = df["attack_type"]

        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=0.2,
            random_state=42,
            stratify=y
        )
        
        # -------------------------
        # 1. Train model
        # -------------------------
        self.model.fit(X_train, y_train)


        # -------------------------
        # 2. FEATURE IMPORTANCE
        # -------------------------
        print("\n=== FEATURE IMPORTANCE ===")

        importances = self.model.feature_importances_
        features = X.columns

        fi_df = pd.DataFrame({
                "feature": features,
                "importance": importances
            }).sort_values(by="importance", ascending=False)
        
        fi_df.to_csv("data/processed/feature_importance.csv",index=False)

        print("\n[+] Feature importance saved to data/processed/feature_importance.csv\n")

        sorted_idx = importances.argsort()[::-1]

        for i in sorted_idx:
            print(f"{features[i]}: {importances[i]:.4f}")

        # -------------------------
        # 3. Predictions
        # -------------------------
        predictions = self.model.predict(X_test)

        print("\n=== CLASS DISTRIBUTION IN TEST SET ===\n")
        print(y_test.value_counts())

        print("\n=== MODEL PREDICTIONS ===\n")
        print(pd.Series(predictions).value_counts())

        # -----------------------------
        # 4. Classification Report
        # -----------------------------
        print("\n=== CLASSIFICATION REPORT ===\n")
        print(classification_report(y_test, predictions, zero_division=0))

        # -----------------------------
        # 5. Confusion Matrix
        # -----------------------------
        cm = confusion_matrix(y_test, predictions)

        plt.figure(figsize=(8, 6))
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=self.model.classes_,
            yticklabels=self.model.classes_
        )

        plt.title("Confusion Matrix - Attack Classification")
        plt.xlabel("Predicted")
        plt.ylabel("Actual")

        plt.tight_layout()
        plt.savefig("data/processed/confusion_matrix.png")

        print("\n[+] Confusion matrix saved")

        return self

    def save(self, path):

        joblib.dump(self.model, path)

        print(f"[+] Model saved to {path}")