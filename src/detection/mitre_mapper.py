class MitreMapper:

    ATTACKS = {

        "nmap_scan":
        "T1046",

        "hydra_attack":
        "T1110",

        "dos_attack":
        "T1498"
    }

    @staticmethod
    def map_attack(
        attack_name
    ):

        return (

            MitreMapper
            .ATTACKS
            .get(
                attack_name,
                "UNKNOWN"
            )

        )