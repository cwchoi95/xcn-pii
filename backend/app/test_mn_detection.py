from app.pii import detect_all


def test_mn_detects_dot_separated_phone_number() -> None:
    found = detect_all("연락처는 010.1234.1258 입니다.", max_results_per_type=20)
    matches = [item.get("matchString") for item in found.get("MN", [])]
    assert "010.1234.1258" in matches
