class SeverityEngine:
    """
    Converts ML predictions into SOC-grade security intelligence.

    Adds:
    - Severity scoring (LOW, MEDIUM, HIGH, CRITICAL)
    - MITRE ATT&CK mapping
    - Risk scoring (0–100)
    """

    def __init__(self):

        # -------------------------------------------------
        # Attack intelligence mapping (SOC knowledge base)
        # -------------------------------------------------
        self.mapping = {

            # Normal traffic
            "normal": {
                "severity": "LOW",
                "score": 5,
                "mitre": "-"
            },

            # Port scanning (reconnaissance)
            "nmap": {
                "severity": "MEDIUM",
                "score": 50,
                "mitre": "T1046 - Network Service Discovery"
            },

            # SSH brute force attack
            "hydra": {
                "severity": "HIGH",
                "score": 80,
                "mitre": "T1110 - Brute Force"
            },

            # Denial of Service attack
            "dos": {
                "severity": "CRITICAL",
                "score": 95,
                "mitre": "T1498 - Network Denial of Service"
            }
        }

    def evaluate(self, attack_type: str) -> dict:
        """
        Returns SOC intelligence for a given prediction.

        Args:
            attack_type (str): ML model prediction label

        Returns:
            dict: severity, score, MITRE mapping
        """

        # Default fallback if unknown label appears
        if attack_type not in self.mapping:

            return {
                "severity": "UNKNOWN",
                "score": 0,
                "mitre": "Unknown Technique"
            }

        return self.mapping[attack_type]

    def is_critical(self, attack_type: str) -> bool:
        """
        Quick helper used for alert filtering.

        Returns True if attack is CRITICAL severity.
        """

        return self.mapping.get(attack_type, {}).get("severity") == "CRITICAL"