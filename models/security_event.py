class SecurityEvent:

    def __init__(
        self,
        timestamp=None,
        user=None,
        host=None,
        activity=None,
        src_ip=None,
        dst_ip=None,
        protocol=None,
        url=None,
        label=None,
        dataset_type=None
    ):

        self.timestamp = timestamp
        self.user = user
        self.host = host
        self.activity = activity
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.url = url
        self.label = label
        self.dataset_type = dataset_type