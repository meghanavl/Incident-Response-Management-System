import pandas as pd
import random


class LogIngestor:

    def __init__(self, path="data/logon.csv"):

        self.logs = pd.read_csv(path)

        self.logs = self.logs.sort_values(
            by="date"
        )

    def fetch_logs(self):

        # -----------------------------------
        # RANDOM INCIDENT WINDOW
        # -----------------------------------

        max_start = len(self.logs) - 200

        start_index = random.randint(0, max_start)

        sampled_logs = self.logs.iloc[
            start_index:start_index + 200
        ]

        return sampled_logs