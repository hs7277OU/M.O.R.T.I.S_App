from app.scanner.risk import make_finding, overall_rating
def test_overall_rating_uses_highest_finding():
 findings = [
 make_finding("Test", "Low item", "Low", "desc", "rec"),
 make_finding("Test", "High item", "High", "desc", "rec"),
 ]
 score, rating = overall_rating(findings)
 assert score == 8
 assert rating == "High"
 