from sklearn.ensemble import IsolationForest
import joblib


class AnomalyDetector:

    def __init__(self):

        self.model = IsolationForest(

            contamination=0.05,

            random_state=42
        )

    def train(
        self,
        features
    ):

        X = features.drop(
            columns=["src_ip"]
        )

        self.model.fit(X)

        return self

    def predict(
        self,
        features
    ):

        X = features.drop(
            columns=["src_ip"]
        )

        return self.model.predict(X)

    def save(
        self,
        path
    ):

        joblib.dump(
            self.model,
            path
        )