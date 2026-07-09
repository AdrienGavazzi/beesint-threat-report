import polars as pl

from beesint_threat_report.load.parquet_writer import (
    read_latest_historical_parquet,
    write_historical_parquet,
)


def test_write_then_read_roundtrip(tmp_path):
    df = pl.DataFrame({"cve_id": ["CVE-2026-10001", "CVE-2026-10002"], "cvss_v3_score": [9.8, 8.6]})
    base_path = str(tmp_path)

    written_path = write_historical_parquet(
        df,
        source="nvd",
        period_end="20260608",
        run_id="run-1",
        base_path=base_path,
        storage_options=None,
    )
    assert written_path.endswith("run-run-1.parquet")

    read_back = read_latest_historical_parquet(source="nvd", base_path=base_path, storage_options=None)
    assert read_back is not None
    assert read_back.equals(df)


def test_read_latest_historical_parquet_empty_base_returns_none(tmp_path):
    result = read_latest_historical_parquet(source="nvd", base_path=str(tmp_path), storage_options=None)
    assert result is None


def test_read_latest_historical_parquet_picks_most_recent(tmp_path):
    base_path = str(tmp_path)
    df1 = pl.DataFrame({"x": [1]})
    df2 = pl.DataFrame({"x": [2]})
    write_historical_parquet(df1, "feodo", "20260601", "run-old", base_path, None)
    write_historical_parquet(df2, "feodo", "20260608", "run-new", base_path, None)

    result = read_latest_historical_parquet("feodo", base_path, None)
    assert result.equals(df2)
