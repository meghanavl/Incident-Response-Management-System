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

        sample_size = min(
            200,
            len(self.logs)
        )

        return self.logs.sample(

            sample_size,

            replace=False
        )