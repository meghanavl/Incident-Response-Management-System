class LateralMovementDetector:

    def detect(self, events):

        previous_host = None

        movement_count = 0

        high_risk_hosts = []

        for event in events:

            if event.dataset_type != "CMU_CERT":

                continue

            if (

                previous_host and

                previous_host != event.host
            ):

                movement_count += 1

                high_risk_hosts.append(
                    event.host
                )

            previous_host = event.host

        return {

            "LateralMovement":
            movement_count,

            "HighRiskHosts":
            list(set(high_risk_hosts))
        }