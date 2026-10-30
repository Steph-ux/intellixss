from pathlib import Path

from intellixss.models import InjectionContext, ScanResult, XSSFinding
from intellixss.report.html_report import write_html_report


def test_html_report_writes(tmp_path: Path):
    result = ScanResult(
        target_url="https://ex.com/level1",
        findings=[
            XSSFinding(
                url="https://ex.com/level1/frame?q=1",
                parameter="query",
                method="GET",
                context=InjectionContext.HTML_TEXT,
                payload="<svg/onload=alert(1)>",
                evidence="browser_dialog:dialog_on_load",
                browser_confirmed=True,
                vulnerability_type="reflected",
                confidence=0.95,
            )
        ],
        targets_tested=1,
    )
    out = tmp_path / "report.html"
    path = write_html_report(result, str(out))
    text = Path(path).read_text(encoding="utf-8")
    assert "IntelliXSS" in text
    assert "CONFIRMED" in text
    assert "query" in text
    assert "svg/onload" in text
    # New report contract: severity, CVSS vector and remediation are present
    assert "CVSS" in text
    assert "CVSS:3.1/" in text
    assert "Remediation" in text
    assert "MEDIUM" in text


def test_html_report_empty_result(tmp_path: Path):
    result = ScanResult(target_url="https://ex.com/")
    text = Path(write_html_report(result, str(tmp_path / "r.html"))).read_text(
        encoding="utf-8"
    )
    assert "No XSS confirmed" in text
    assert "No findings." in text
