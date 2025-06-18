from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


@dataclass
class Report:
    """Estrutura padrao do relatorio resumido."""

    date: str
    total_iocs: int
    by_source: Dict[str, int]
    by_type: Dict[str, int]
    duplicates: Dict[str, List[str]]
    top_values: List[tuple]
    iocs: List[Dict[str, Any]]
    coverage: Dict[str, float] = field(default_factory=dict)
    missing_feeds: List[str] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)

@dataclass
class IOC:
    """Schema padrao para indicadores de comprometimento."""

    date: str
    source: str
    ioc_type: str
    ioc_value: str
    time: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    mitigation: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        extra = data.pop("extra", {})
        data.update(extra)
        return data
