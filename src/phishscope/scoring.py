from dataclasses import dataclass

CATEGORY_CAPS = {
    "auth": 45,
    "headers": 45,
    "urls": 45,
    "attachments": 50,
    "content": 20,
    "reputation": 60,
}

VERDICTS = [
    (70, "Malicious"),
    (40, "Likely phishing"),
    (15, "Suspicious"),
    (0, "Clean"),
]


def severity_for(points):
    if points == 0:
        return "info"
    if points < 10:
        return "low"
    if points < 20:
        return "medium"
    if points < 35:
        return "high"
    return "critical"


@dataclass
class Finding:
    category: str
    message: str
    points: int = 0
    floor: int = 0
    severity: str = ""

    def __post_init__(self):
        if not self.severity:
            self.severity = severity_for(self.points)


def score(findings):
    totals = {}
    for f in findings:
        totals[f.category] = totals.get(f.category, 0) + f.points
    capped = sum(min(total, CATEGORY_CAPS.get(cat, 30)) for cat, total in totals.items())
    floor = max((f.floor for f in findings), default=0)
    return min(100, max(capped, floor))


def verdict(value):
    for threshold, label in VERDICTS:
        if value >= threshold:
            return label
    return "Clean"
