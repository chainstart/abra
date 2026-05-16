"""Agent 编排层数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class TaskStep:
    """单个任务步骤。"""

    name: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class AgentTaskResult:
    """统一任务输出。"""

    task_type: str
    target: str
    status: str
    steps: list[TaskStep] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "task_type": self.task_type,
            "target": self.target,
            "status": self.status,
            "steps": [step.to_dict() for step in self.steps],
            "payload": self.payload,
        }
