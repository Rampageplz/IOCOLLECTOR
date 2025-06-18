import json
from pathlib import Path

from ioc_collector.report import generate_report, _save_csv, _save_txt, _save_json


def test_generate_and_save_report(tmp_path):
    report = generate_report("2025-06-18", top_count=5)
    csv_path = tmp_path / "out.csv"
    txt_path = tmp_path / "out.txt"
    json_path = tmp_path / "out.json"
    _save_csv(report, csv_path)
    _save_txt(report, txt_path)
    _save_json(report, json_path)
    assert csv_path.exists()
    assert txt_path.exists()
    assert json_path.exists()
    data = json.loads(json_path.read_text())
    assert data["total_iocs"] == report.total_iocs
