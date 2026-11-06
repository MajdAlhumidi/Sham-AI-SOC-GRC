import pytest

from scripts.grc.scoring import calculate_risk_score


@pytest.mark.parametrize(
    ("likelihood", "impact", "expected"),
    [
        (1, 1, (1, "Low")),
        (2, 2, (4, "Low")),
        (3, 3, (9, "Medium")),
        (4, 3, (12, "High")),
        (5, 5, (25, "Critical")),
    ],
)
def test_calculate_risk_score(likelihood, impact, expected):
    assert calculate_risk_score(likelihood, impact) == expected


@pytest.mark.parametrize(("likelihood", "impact"), [(0, 3), (6, 2), (2, 0), (3, 6)])
def test_risk_score_rejects_values_outside_the_5x5_matrix(likelihood, impact):
    with pytest.raises(ValueError):
        calculate_risk_score(likelihood, impact)
