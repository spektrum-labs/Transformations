"""Self-hosted OFAC sanctions screening service.

OFAC publishes the SDN and Consolidated lists only as bulk XML (there is no free
per-name query API), so screening is performed locally against a hosted copy of
the data. See ``README.md`` for the deployment/sync model.
"""

__version__ = "1.0.0"
