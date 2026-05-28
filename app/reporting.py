def generate_report(target_url: str, findings: list[dict], overall_rating: str) -> str:
 """MVP report generator. Replace this with Claude/OpenAI API integration later."""
 risky = [f for f in findings if f.get("severity") in {"Medium", "High", "Critical"}]
 if not risky:
    return f"MORTIS completed a baseline scan of {target_url}. No major issues were identified during this limited MVP scan. Further authenticated and deeper testing is still recommended."
 
 top = sorted(risky, key=lambda f: f.get("score", 0), reverse=True)[:3]
 lines = [
 f"MORTIS completed a baseline scan of {target_url}.",
 f"Overall risk rating: {overall_rating}.",
 "The most important issues to review are:",
 ]
 for item in top:
    lines.append(f"- {item['title']} ({item['severity']}): {item['recommendation']}")
 lines.append("This report is an initial draft and should be reviewed by a human tester before being used in a formal penetration-testing report.")
 return "\n".join(lines)