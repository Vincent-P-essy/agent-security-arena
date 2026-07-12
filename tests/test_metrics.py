import pytest

from agent_security_arena.metrics import percentile, rate_estimate


def test_wilson_interval_contains_observed_rate() -> None:
    estimate = rate_estimate([True, True, False, False, False])

    assert estimate.rate == 0.4
    assert estimate.ci95_low < estimate.rate < estimate.ci95_high


def test_empty_rate_is_explicit() -> None:
    estimate = rate_estimate([])
    assert estimate.denominator == 0
    assert estimate.rate == 0


@pytest.mark.parametrize(("quantile", "expected"), [(0, 1), (0.5, 2.5), (0.95, 3.85), (1, 4)])
def test_percentile_interpolates(quantile: float, expected: float) -> None:
    assert percentile([1, 2, 3, 4], quantile) == pytest.approx(expected)
