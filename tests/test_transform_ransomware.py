from datetime import UTC, datetime

from beesint_threat_report.transform.ransomware import build_group_aggregates, build_sector_breakdown
from beesint_threat_report.validate.schemas import RansomwareGroup, RansomwarePost


def _post(group_name: str, activity: str, discovered: str) -> RansomwarePost:
    return RansomwarePost(group_name=group_name, activity=activity, discovered=discovered)


def test_build_group_aggregates_counts_and_sorts_desc():
    period_end = datetime(2026, 7, 18, tzinfo=UTC)
    posts_this_week = [
        _post("lockbit3", "Healthcare", "2026-07-16T00:00:00+00:00"),
        _post("lockbit3", "Manufacturing", "2026-07-17T00:00:00+00:00"),
        _post("akira", "Retail", "2026-07-15T00:00:00+00:00"),
    ]
    result = build_group_aggregates(posts_this_week, posts_this_week, {}, period_end)
    assert [g["name"] for g in result] == ["lockbit3", "akira"]
    assert result[0]["count"] == 2
    assert result[1]["count"] == 1


def test_build_group_aggregates_joins_lifetime_and_raas_via_normalized_name():
    period_end = datetime(2026, 7, 18, tzinfo=UTC)
    posts = [_post("LockBit3", "Healthcare", "2026-07-16T00:00:00+00:00")]
    groups = {"lockbit3": RansomwareGroup(name="LockBit3", is_raas=True, victim_count_lifetime=1200)}
    result = build_group_aggregates(posts, posts, groups, period_end)
    assert result[0]["victim_count_lifetime"] == 1200
    assert result[0]["is_raas"] is True
    assert result[0]["profile_url"] == "https://www.ransomware.live/group/lockbit3"


def test_build_group_aggregates_defaults_when_group_not_in_profiles():
    period_end = datetime(2026, 7, 18, tzinfo=UTC)
    posts = [_post("unknowngroup", "Retail", "2026-07-16T00:00:00+00:00")]
    result = build_group_aggregates(posts, posts, {}, period_end)
    assert result[0]["victim_count_lifetime"] == 0
    assert result[0]["is_raas"] is False


def test_build_group_aggregates_sparkline_buckets_by_week():
    period_end = datetime(2026, 7, 18, tzinfo=UTC)
    posts_this_week = [_post("akira", "Retail", "2026-07-16T00:00:00+00:00")]
    posts_last_weeks = posts_this_week + [
        _post("akira", "Retail", "2026-07-16T00:00:00+00:00"),  # this week, bucket 5 (dernier)
        _post("akira", "Retail", "2026-06-15T00:00:00+00:00"),  # ~5 semaines avant, bucket plus tôt
    ]
    result = build_group_aggregates(posts_this_week, posts_last_weeks, {}, period_end, weeks=6)
    buckets = result[0]["sparkline_weekly_counts"]
    assert len(buckets) == 6
    assert buckets[-1] == 2  # les 2 posts de cette semaine
    assert sum(buckets) == 3


def test_build_sector_breakdown_groups_by_activity_with_pct():
    posts = [
        _post("a", "Healthcare", "2026-07-16T00:00:00+00:00"),
        _post("b", "Healthcare", "2026-07-16T00:00:00+00:00"),
        _post("c", "Retail", "2026-07-16T00:00:00+00:00"),
    ]
    result = build_sector_breakdown(posts)
    by_sector = {r["sector"]: r for r in result}
    assert by_sector["Healthcare"]["count"] == 2
    assert by_sector["Healthcare"]["pct_of_total"] == round(2 / 3 * 100, 1)
    assert by_sector["Retail"]["count"] == 1


def test_build_sector_breakdown_empty_when_no_posts():
    assert build_sector_breakdown([]) == []
