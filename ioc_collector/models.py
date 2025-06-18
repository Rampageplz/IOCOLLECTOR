from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List

@dataclass
class IOC:
    """Schema padrao para indicadores de comprometimento."""

    date: str
    source: str
    ioc_type: str
    ioc_value: str
    description: str = ""
    tags: List[str] = field(default_factory=list)
    mitigation: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        extra = data.pop("extra", {})
        data.update(extra)
        return data
