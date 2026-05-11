import pandas as pd

class LogIngestor:

    def __init__(self, path):

        self.logs = pd.read_csv(path)

        # -----------------------------------
        # SORT ONLY IF DATE EXISTS
        # -----------------------------------

        if "date" in self.logs.columns:

            self.logs = self.logs.sort_values(
                by="date"
            )

    def fetch_logs(self):

        # -----------------------------------
        # CLEAN COLUMN NAMES
        # -----------------------------------

        self.logs.columns = (
            self.logs.columns.str.strip()
        )

        # -----------------------------------
        # CIC IDS DATASET
        # -----------------------------------

        if "Label" in self.logs.columns:

            # ATTACK TRAFFIC

            attack_rows = self.logs[

                self.logs["Label"] != "BENIGN"
            ]

            # NORMAL TRAFFIC

            benign_rows = self.logs[

                self.logs["Label"] == "BENIGN"
            ]

            # SAMPLE ATTACKS

            sampled_attacks = attack_rows.sample(

                min(100, len(attack_rows)),

                replace=False
            )

            # SAMPLE BENIGN

            sampled_benign = benign_rows.sample(

                min(100, len(benign_rows)),

                replace=False
            )

            # MERGE THEM

            combined = sampled_attacks._append(

                sampled_benign
            )

            # SHUFFLE

            return combined.sample(
                frac=1
            )

        # -----------------------------------
        # OTHER DATASETS
        # -----------------------------------

        return self.logs.sample(

            200,

            replace=False
        )