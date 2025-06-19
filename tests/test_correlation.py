import pandas as pd
from ioc_collector.report import build_correlation_dataframe


def test_build_correlation_dataframe():
    iocs = [
        {"ioc_value": "1.1.1.1", "ioc_type": "IP", "source": "AbuseIPDB"},
        {"ioc_value": "1.1.1.1", "ioc_type": "IP", "source": "OTX"},
        {"ioc_value": "evil.com", "ioc_type": "URL", "source": "URLHaus"},
    ]
    df = build_correlation_dataframe(iocs)
    row = df[df["ioc_value"] == "1.1.1.1"].iloc[0]
    assert row["source_count"] == 2
    assert set(row["sources"]) == {"AbuseIPDB", "OTX"}
    assert row["risk_score"] == 20
