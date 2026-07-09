import polars as pl

from beesint_threat_report.config import Settings
from beesint_threat_report.transform import diffing
from beesint_threat_report.transform.diffing import diff_snapshots, load_previous_snapshot


def test_diff_snapshots_cold_start_all_new():
    current = pl.DataFrame({"ip_address": ["1.1.1.1", "2.2.2.2"]})
    result = diff_snapshots(current, None, "ip_address")
    assert result["is_new"].to_list() == [True, True]


def test_diff_snapshots_partial_overlap():
    current = pl.DataFrame({"ip_address": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]})
    previous = pl.DataFrame({"ip_address": ["1.1.1.1", "9.9.9.9"]})
    result = diff_snapshots(current, previous, "ip_address")
    is_new_by_ip = dict(zip(result["ip_address"].to_list(), result["is_new"].to_list()))
    assert is_new_by_ip == {"1.1.1.1": False, "2.2.2.2": True, "3.3.3.3": True}


def test_load_previous_snapshot_manifest_none_returns_none(tmp_path):
    settings = Settings(local_data_dir=tmp_path)
    assert load_previous_snapshot(None, "feodo", settings) is None


def test_load_previous_snapshot_corrupted_treated_as_cold_start(tmp_path, monkeypatch):
    settings = Settings(local_data_dir=tmp_path)

    def _raise(*args, **kwargs):
        raise OSError("corrupted parquet")

    monkeypatch.setattr(diffing, "read_latest_historical_parquet", _raise)

    result = load_previous_snapshot({"run_id": "abc"}, "feodo", settings)
    assert result is None
