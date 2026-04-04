"""基于 Solidity AST 的深语义分析。

这一层的目标，不再只是做“函数数量统计”，而是补齐更强的程序结构信息：

- 控制流规模：分支、循环、返回点、条件外部调用
- 数据流摘要：状态变量读写、读写热点、函数间冲突
- 内部调用图：函数到函数的边
- 跨合约调用图：当前函数调用了哪个外部合约/接口的哪个方法
- 高风险执行顺序：外部调用后再写状态

这里依然不是完整的形式化分析器，但已经比简单字符串匹配强很多，
可以为审计报告和后续验证层提供更接近“程序语义”的结构化输入。
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from solidity_parser import parser


LOW_LEVEL_EXTERNAL_MEMBERS = {"call", "delegatecall", "staticcall", "transfer", "send"}
COMMON_EXTERNAL_METHODS = {
    "transfer",
    "transferFrom",
    "approve",
    "balanceOf",
    "mint",
    "burn",
    "deposit",
    "withdraw",
    "borrow",
    "repay",
    "swap",
    "price",
}
LOOP_TYPES = {"WhileStatement", "ForStatement", "DoWhileStatement"}
BRANCH_TYPES = {"IfStatement", "Conditional"}


@dataclass(frozen=True)
class CallEdgeRecord:
    """调用边。"""

    from_contract: str
    from_function: str
    target_contract: str
    target_function: str
    line: int

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "from_contract": self.from_contract,
            "from_function": self.from_function,
            "target_contract": self.target_contract,
            "target_function": self.target_function,
            "line": self.line,
        }


@dataclass(frozen=True)
class StateConflictRecord:
    """状态变量冲突关系。"""

    state_variable: str
    from_function: str
    to_function: str
    conflict_type: str

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "state_variable": self.state_variable,
            "from_function": self.from_function,
            "to_function": self.to_function,
            "conflict_type": self.conflict_type,
        }


@dataclass(frozen=True)
class FunctionSemanticRecord:
    """单个函数的深语义摘要。"""

    contract_name: str
    name: str
    visibility: str
    state_mutability: str
    modifiers: list[str]
    line_start: int
    line_end: int
    reads: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)
    internal_calls: list[str] = field(default_factory=list)
    external_interactions: list[str] = field(default_factory=list)
    require_count: int = 0
    assert_count: int = 0
    loop_count: int = 0
    branch_count: int = 0
    return_count: int = 0
    statement_count: int = 0
    external_call_count: int = 0
    conditional_external_call_count: int = 0
    external_call_then_state_write: bool = False

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "contract_name": self.contract_name,
            "name": self.name,
            "visibility": self.visibility,
            "state_mutability": self.state_mutability,
            "modifiers": self.modifiers,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "reads": self.reads,
            "writes": self.writes,
            "internal_calls": self.internal_calls,
            "external_interactions": self.external_interactions,
            "require_count": self.require_count,
            "assert_count": self.assert_count,
            "loop_count": self.loop_count,
            "branch_count": self.branch_count,
            "return_count": self.return_count,
            "statement_count": self.statement_count,
            "external_call_count": self.external_call_count,
            "conditional_external_call_count": self.conditional_external_call_count,
            "external_call_then_state_write": self.external_call_then_state_write,
        }


@dataclass(frozen=True)
class AstSemanticSummary:
    """AST 级深语义摘要。"""

    contract_names: list[str]
    contract_kinds: dict[str, str]
    inheritance_edges: dict[str, list[str]]
    state_variables: list[str]
    events: list[str]
    public_entrypoints: list[str]
    state_access_map: dict[str, dict[str, list[str]]]
    internal_call_edges: list[CallEdgeRecord]
    cross_contract_call_edges: list[CallEdgeRecord]
    state_conflicts: list[StateConflictRecord]
    write_after_external_functions: list[str]
    functions: list[FunctionSemanticRecord]

    def to_dict(self) -> dict[str, Any]:
        """输出可序列化字典。"""

        return {
            "contract_names": self.contract_names,
            "contract_kinds": self.contract_kinds,
            "inheritance_edges": self.inheritance_edges,
            "state_variables": self.state_variables,
            "events": self.events,
            "public_entrypoints": self.public_entrypoints,
            "state_access_map": self.state_access_map,
            "internal_call_edges": [edge.to_dict() for edge in self.internal_call_edges],
            "cross_contract_call_edges": [
                edge.to_dict() for edge in self.cross_contract_call_edges
            ],
            "state_conflicts": [conflict.to_dict() for conflict in self.state_conflicts],
            "write_after_external_functions": self.write_after_external_functions,
            "functions": [function.to_dict() for function in self.functions],
        }


def _walk(node: Any):
    """递归遍历 AST。"""

    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def _loc_line(node: dict) -> int:
    """提取开始行号。"""

    return node.get("loc", {}).get("start", {}).get("line", 0)


def _loc_bounds(node: dict) -> tuple[int, int]:
    """提取起止行号。"""

    loc = node.get("loc", {})
    start_line = loc.get("start", {}).get("line", 0)
    end_line = loc.get("end", {}).get("line", start_line)
    return start_line, end_line


def _user_defined_type_name(type_name: dict | None) -> str | None:
    """从类型节点里提取自定义类型名。"""

    if not type_name:
        return None
    if type_name.get("type") == "UserDefinedTypeName":
        return type_name.get("namePath")
    return None


def _collect_contract_reference_vars(
    contract_node: dict,
    known_contract_names: set[str],
) -> dict[str, str]:
    """收集合约级引用变量。

    例如：

    - `IERC20 public token;`
    - `Foo internal foo;`
    """

    contract_refs: dict[str, str] = {}
    for sub_node in contract_node.get("subNodes") or []:
        if sub_node.get("type") != "StateVariableDeclaration":
            continue
        type_name = None
        for variable in sub_node.get("variables") or []:
            type_name = _user_defined_type_name(variable.get("typeName"))
            variable_name = variable.get("name")
            if type_name in known_contract_names and variable_name:
                contract_refs[variable_name] = type_name
    return contract_refs


def _extract_lvalue_state_name(node: dict, state_vars: set[str]) -> str | None:
    """从左值节点中提取状态变量名。"""

    node_type = node.get("type")
    if node_type == "Identifier":
        name = node.get("name")
        return name if name in state_vars else None
    if node_type == "IndexAccess":
        base = node.get("base", {})
        if base.get("type") == "Identifier":
            name = base.get("name")
            return name if name in state_vars else None
    if node_type == "MemberAccess":
        expression = node.get("expression", {})
        if expression.get("type") == "Identifier":
            name = expression.get("name")
            return name if name in state_vars else None
    return None


def _infer_target_contract(expression: dict, contract_refs: dict[str, str]) -> str | None:
    """从调用表达式中推断目标合约。"""

    expr_type = expression.get("type")
    if expr_type == "Identifier":
        return contract_refs.get(expression.get("name"))
    if expr_type == "FunctionCall":
        inner = expression.get("expression", {})
        if inner.get("type") == "Identifier":
            return inner.get("name")
    if expr_type == "IndexAccess":
        base = expression.get("base", {})
        if base.get("type") == "Identifier":
            return contract_refs.get(base.get("name"))
    if expr_type == "MemberAccess":
        inner = expression.get("expression", {})
        return _infer_target_contract(inner, contract_refs)
    return None


def _register_local_contract_refs(node: dict, contract_refs: dict[str, str], known_contract_names: set[str]) -> None:
    """把局部变量声明中的合约引用记录下来。"""

    if node.get("type") != "VariableDeclarationStatement":
        return
    for variable in node.get("variables") or []:
        type_name = _user_defined_type_name(variable.get("typeName"))
        variable_name = variable.get("name")
        if type_name in known_contract_names and variable_name:
            contract_refs[variable_name] = type_name


def _analyze_expression(
    node: dict,
    *,
    state_vars: set[str],
    known_function_names: set[str],
    contract_refs: dict[str, str],
    internal_call_edges: list[CallEdgeRecord],
    cross_contract_edges: list[CallEdgeRecord],
    current_contract: str,
    current_function: str,
    reads: set[str],
    writes: set[str],
    internal_calls: set[str],
    external_interactions: set[str],
    event_log: list[tuple[str, str]],
    counters: dict[str, int],
) -> None:
    """分析表达式节点。"""

    node_type = node.get("type")
    if node_type == "Identifier":
        name = node.get("name", "")
        if name in state_vars:
            reads.add(name)
        return

    if node_type == "BinaryOperation":
        operator = node.get("operator")
        left = node.get("left", {})
        right = node.get("right", {})
        if operator in {"=", "+=", "-=", "*=", "/=", "%="}:
            state_name = _extract_lvalue_state_name(left, state_vars)
            if state_name:
                writes.add(state_name)
                event_log.append(("state_write", state_name))
            _analyze_expression(
                right,
                state_vars=state_vars,
                known_function_names=known_function_names,
                contract_refs=contract_refs,
                internal_call_edges=internal_call_edges,
                cross_contract_edges=cross_contract_edges,
                current_contract=current_contract,
                current_function=current_function,
                reads=reads,
                writes=writes,
                internal_calls=internal_calls,
                external_interactions=external_interactions,
                event_log=event_log,
                counters=counters,
            )
            if left.get("type") == "IndexAccess":
                _analyze_expression(
                    left.get("index", {}),
                    state_vars=state_vars,
                    known_function_names=known_function_names,
                    contract_refs=contract_refs,
                    internal_call_edges=internal_call_edges,
                    cross_contract_edges=cross_contract_edges,
                    current_contract=current_contract,
                    current_function=current_function,
                    reads=reads,
                    writes=writes,
                    internal_calls=internal_calls,
                    external_interactions=external_interactions,
                    event_log=event_log,
                    counters=counters,
                )
            return

        _analyze_expression(
            left,
            state_vars=state_vars,
            known_function_names=known_function_names,
            contract_refs=contract_refs,
            internal_call_edges=internal_call_edges,
            cross_contract_edges=cross_contract_edges,
            current_contract=current_contract,
            current_function=current_function,
            reads=reads,
            writes=writes,
            internal_calls=internal_calls,
            external_interactions=external_interactions,
            event_log=event_log,
            counters=counters,
        )
        _analyze_expression(
            right,
            state_vars=state_vars,
            known_function_names=known_function_names,
            contract_refs=contract_refs,
            internal_call_edges=internal_call_edges,
            cross_contract_edges=cross_contract_edges,
            current_contract=current_contract,
            current_function=current_function,
            reads=reads,
            writes=writes,
            internal_calls=internal_calls,
            external_interactions=external_interactions,
            event_log=event_log,
            counters=counters,
        )
        return

    if node_type == "UnaryOperation":
        sub = node.get("subExpression", {})
        state_name = _extract_lvalue_state_name(sub, state_vars)
        if state_name:
            reads.add(state_name)
            writes.add(state_name)
            event_log.append(("state_write", state_name))
        _analyze_expression(
            sub,
            state_vars=state_vars,
            known_function_names=known_function_names,
            contract_refs=contract_refs,
            internal_call_edges=internal_call_edges,
            cross_contract_edges=cross_contract_edges,
            current_contract=current_contract,
            current_function=current_function,
            reads=reads,
            writes=writes,
            internal_calls=internal_calls,
            external_interactions=external_interactions,
            event_log=event_log,
            counters=counters,
        )
        return

    if node_type == "FunctionCall":
        expression = node.get("expression", {})
        expr_type = expression.get("type")
        line = _loc_line(node)
        if expr_type == "Identifier":
            called_name = expression.get("name", "")
            if called_name in {"require", "revert"}:
                counters["require_count"] += 1
            elif called_name == "assert":
                counters["assert_count"] += 1
            elif called_name in known_function_names:
                internal_calls.add(called_name)
                internal_call_edges.append(
                    CallEdgeRecord(
                        from_contract=current_contract,
                        from_function=current_function,
                        target_contract=current_contract,
                        target_function=called_name,
                        line=line,
                    )
                )
                event_log.append(("internal_call", called_name))
        elif expr_type == "MemberAccess":
            member_name = expression.get("memberName", "")
            target_contract = _infer_target_contract(expression.get("expression", {}), contract_refs)
            if target_contract or member_name in LOW_LEVEL_EXTERNAL_MEMBERS or member_name in COMMON_EXTERNAL_METHODS:
                external_interactions.add(member_name)
                counters["external_call_count"] += 1
                event_log.append(("external_call", member_name))
                cross_contract_edges.append(
                    CallEdgeRecord(
                        from_contract=current_contract,
                        from_function=current_function,
                        target_contract=target_contract or "<unknown>",
                        target_function=member_name,
                        line=line,
                    )
                )

        for argument in node.get("arguments", []):
            _analyze_expression(
                argument,
                state_vars=state_vars,
                known_function_names=known_function_names,
                contract_refs=contract_refs,
                internal_call_edges=internal_call_edges,
                cross_contract_edges=cross_contract_edges,
                current_contract=current_contract,
                current_function=current_function,
                reads=reads,
                writes=writes,
                internal_calls=internal_calls,
                external_interactions=external_interactions,
                event_log=event_log,
                counters=counters,
            )
        if expr_type == "MemberAccess":
            _analyze_expression(
                expression.get("expression", {}),
                state_vars=state_vars,
                known_function_names=known_function_names,
                contract_refs=contract_refs,
                internal_call_edges=internal_call_edges,
                cross_contract_edges=cross_contract_edges,
                current_contract=current_contract,
                current_function=current_function,
                reads=reads,
                writes=writes,
                internal_calls=internal_calls,
                external_interactions=external_interactions,
                event_log=event_log,
                counters=counters,
            )
        return

    if node_type in {"MemberAccess", "IndexAccess", "TupleExpression"}:
        for child in _walk(node):
            if child is node:
                continue
            if isinstance(child, dict) and child.get("type") == "Identifier":
                name = child.get("name", "")
                if name in state_vars:
                    reads.add(name)
        return

    for child in _walk(node):
        if child is node:
            continue
        if isinstance(child, dict):
            _analyze_expression(
                child,
                state_vars=state_vars,
                known_function_names=known_function_names,
                contract_refs=contract_refs,
                internal_call_edges=internal_call_edges,
                cross_contract_edges=cross_contract_edges,
                current_contract=current_contract,
                current_function=current_function,
                reads=reads,
                writes=writes,
                internal_calls=internal_calls,
                external_interactions=external_interactions,
                event_log=event_log,
                counters=counters,
            )


def _analyze_statement(
    node: dict,
    *,
    state_vars: set[str],
    known_function_names: set[str],
    contract_refs: dict[str, str],
    known_contract_names: set[str],
    internal_call_edges: list[CallEdgeRecord],
    cross_contract_edges: list[CallEdgeRecord],
    current_contract: str,
    current_function: str,
    reads: set[str],
    writes: set[str],
    internal_calls: set[str],
    external_interactions: set[str],
    event_log: list[tuple[str, str]],
    counters: dict[str, int],
) -> None:
    """按语句顺序分析控制流与数据流。"""

    if not node:
        return
    node_type = node.get("type")
    if node_type in {"Block", "UncheckedStatement"}:
        for statement in node.get("statements", []):
            _analyze_statement(
                statement,
                state_vars=state_vars,
                known_function_names=known_function_names,
                contract_refs=contract_refs,
                known_contract_names=known_contract_names,
                internal_call_edges=internal_call_edges,
                cross_contract_edges=cross_contract_edges,
                current_contract=current_contract,
                current_function=current_function,
                reads=reads,
                writes=writes,
                internal_calls=internal_calls,
                external_interactions=external_interactions,
                event_log=event_log,
                counters=counters,
            )
        return

    counters["statement_count"] += 1
    _register_local_contract_refs(node, contract_refs, known_contract_names)

    if node_type in LOOP_TYPES:
        counters["loop_count"] += 1
        _analyze_statement(
            node.get("body", {}),
            state_vars=state_vars,
            known_function_names=known_function_names,
            contract_refs=contract_refs,
            known_contract_names=known_contract_names,
            internal_call_edges=internal_call_edges,
            cross_contract_edges=cross_contract_edges,
            current_contract=current_contract,
            current_function=current_function,
            reads=reads,
            writes=writes,
            internal_calls=internal_calls,
            external_interactions=external_interactions,
            event_log=event_log,
            counters=counters,
        )
        for key in ("initExpression", "conditionExpression", "loopExpression"):
            expression = node.get(key)
            if isinstance(expression, dict):
                _analyze_expression(
                    expression,
                    state_vars=state_vars,
                    known_function_names=known_function_names,
                    contract_refs=contract_refs,
                    internal_call_edges=internal_call_edges,
                    cross_contract_edges=cross_contract_edges,
                    current_contract=current_contract,
                    current_function=current_function,
                    reads=reads,
                    writes=writes,
                    internal_calls=internal_calls,
                    external_interactions=external_interactions,
                    event_log=event_log,
                    counters=counters,
                )
        return

    if node_type == "IfStatement":
        counters["branch_count"] += 1
        _analyze_expression(
            node.get("condition", {}),
            state_vars=state_vars,
            known_function_names=known_function_names,
            contract_refs=contract_refs,
            internal_call_edges=internal_call_edges,
            cross_contract_edges=cross_contract_edges,
            current_contract=current_contract,
            current_function=current_function,
            reads=reads,
            writes=writes,
            internal_calls=internal_calls,
            external_interactions=external_interactions,
            event_log=event_log,
            counters=counters,
        )
        before_external_count = counters["external_call_count"]
        _analyze_statement(
            node.get("trueBody", {}),
            state_vars=state_vars,
            known_function_names=known_function_names,
            contract_refs=contract_refs,
            known_contract_names=known_contract_names,
            internal_call_edges=internal_call_edges,
            cross_contract_edges=cross_contract_edges,
            current_contract=current_contract,
            current_function=current_function,
            reads=reads,
            writes=writes,
            internal_calls=internal_calls,
            external_interactions=external_interactions,
            event_log=event_log,
            counters=counters,
        )
        _analyze_statement(
            node.get("falseBody", {}),
            state_vars=state_vars,
            known_function_names=known_function_names,
            contract_refs=contract_refs,
            known_contract_names=known_contract_names,
            internal_call_edges=internal_call_edges,
            cross_contract_edges=cross_contract_edges,
            current_contract=current_contract,
            current_function=current_function,
            reads=reads,
            writes=writes,
            internal_calls=internal_calls,
            external_interactions=external_interactions,
            event_log=event_log,
            counters=counters,
        )
        counters["conditional_external_call_count"] += max(
            counters["external_call_count"] - before_external_count,
            0,
        )
        return

    if node_type == "ReturnStatement":
        counters["return_count"] += 1
        expression = node.get("expression")
        if isinstance(expression, dict):
            _analyze_expression(
                expression,
                state_vars=state_vars,
                known_function_names=known_function_names,
                contract_refs=contract_refs,
                internal_call_edges=internal_call_edges,
                cross_contract_edges=cross_contract_edges,
                current_contract=current_contract,
                current_function=current_function,
                reads=reads,
                writes=writes,
                internal_calls=internal_calls,
                external_interactions=external_interactions,
                event_log=event_log,
                counters=counters,
            )
        return

    if node_type == "VariableDeclarationStatement":
        initial_value = node.get("initialValue")
        if isinstance(initial_value, dict):
            _analyze_expression(
                initial_value,
                state_vars=state_vars,
                known_function_names=known_function_names,
                contract_refs=contract_refs,
                internal_call_edges=internal_call_edges,
                cross_contract_edges=cross_contract_edges,
                current_contract=current_contract,
                current_function=current_function,
                reads=reads,
                writes=writes,
                internal_calls=internal_calls,
                external_interactions=external_interactions,
                event_log=event_log,
                counters=counters,
            )
        return

    if node_type == "ExpressionStatement":
        expression = node.get("expression")
        if isinstance(expression, dict):
            _analyze_expression(
                expression,
                state_vars=state_vars,
                known_function_names=known_function_names,
                contract_refs=contract_refs,
                internal_call_edges=internal_call_edges,
                cross_contract_edges=cross_contract_edges,
                current_contract=current_contract,
                current_function=current_function,
                reads=reads,
                writes=writes,
                internal_calls=internal_calls,
                external_interactions=external_interactions,
                event_log=event_log,
                counters=counters,
            )
        return

    if node_type == "EmitStatement":
        event_call = node.get("eventCall", {})
        _analyze_expression(
            event_call,
            state_vars=state_vars,
            known_function_names=known_function_names,
            contract_refs=contract_refs,
            internal_call_edges=internal_call_edges,
            cross_contract_edges=cross_contract_edges,
            current_contract=current_contract,
            current_function=current_function,
            reads=reads,
            writes=writes,
            internal_calls=internal_calls,
            external_interactions=external_interactions,
            event_log=event_log,
            counters=counters,
        )
        return

    for child in _walk(node):
        if child is node:
            continue
        if isinstance(child, dict) and "type" in child:
            _analyze_statement(
                child,
                state_vars=state_vars,
                known_function_names=known_function_names,
                contract_refs=contract_refs,
                known_contract_names=known_contract_names,
                internal_call_edges=internal_call_edges,
                cross_contract_edges=cross_contract_edges,
                current_contract=current_contract,
                current_function=current_function,
                reads=reads,
                writes=writes,
                internal_calls=internal_calls,
                external_interactions=external_interactions,
                event_log=event_log,
                counters=counters,
            )


def _extract_function_semantics(
    *,
    contract_name: str,
    function_node: dict,
    known_function_names: set[str],
    contract_refs: dict[str, str],
    known_contract_names: set[str],
    state_vars: set[str],
    internal_call_edges: list[CallEdgeRecord],
    cross_contract_edges: list[CallEdgeRecord],
) -> FunctionSemanticRecord:
    """抽取函数深语义。"""

    name = function_node.get("name") or "<anonymous>"
    visibility = function_node.get("visibility") or "default"
    state_mutability = function_node.get("stateMutability") or "nonpayable"
    modifiers = [
        modifier.get("name")
        for modifier in function_node.get("modifiers") or []
        if modifier.get("name")
    ]
    line_start, line_end = _loc_bounds(function_node)

    # 函数参数如果是合约引用，也记录下来，便于推断跨合约调用。
    local_contract_refs = dict(contract_refs)
    for parameter in ((function_node.get("parameters") or {}).get("parameters") or []):
        type_name = _user_defined_type_name(parameter.get("typeName"))
        parameter_name = parameter.get("name")
        if type_name in known_contract_names and parameter_name:
            local_contract_refs[parameter_name] = type_name

    reads: set[str] = set()
    writes: set[str] = set()
    internal_calls: set[str] = set()
    external_interactions: set[str] = set()
    event_log: list[tuple[str, str]] = []
    counters = {
        "require_count": 0,
        "assert_count": 0,
        "loop_count": 0,
        "branch_count": 0,
        "return_count": 0,
        "statement_count": 0,
        "external_call_count": 0,
        "conditional_external_call_count": 0,
    }

    body = function_node.get("body") or {}
    _analyze_statement(
        body,
        state_vars=state_vars,
        known_function_names=known_function_names,
        contract_refs=local_contract_refs,
        known_contract_names=known_contract_names,
        internal_call_edges=internal_call_edges,
        cross_contract_edges=cross_contract_edges,
        current_contract=contract_name,
        current_function=name,
        reads=reads,
        writes=writes,
        internal_calls=internal_calls,
        external_interactions=external_interactions,
        event_log=event_log,
        counters=counters,
    )

    saw_external = False
    external_call_then_state_write = False
    for event_type, _payload in event_log:
        if event_type == "external_call":
            saw_external = True
        elif event_type == "state_write" and saw_external:
            external_call_then_state_write = True
            break

    return FunctionSemanticRecord(
        contract_name=contract_name,
        name=name,
        visibility=visibility,
        state_mutability=state_mutability,
        modifiers=modifiers,
        line_start=line_start,
        line_end=line_end,
        reads=sorted(item for item in reads if item),
        writes=sorted(item for item in writes if item),
        internal_calls=sorted(item for item in internal_calls if item),
        external_interactions=sorted(item for item in external_interactions if item),
        require_count=counters["require_count"],
        assert_count=counters["assert_count"],
        loop_count=counters["loop_count"],
        branch_count=counters["branch_count"],
        return_count=counters["return_count"],
        statement_count=counters["statement_count"],
        external_call_count=counters["external_call_count"],
        conditional_external_call_count=counters["conditional_external_call_count"],
        external_call_then_state_write=external_call_then_state_write,
    )


def _build_state_access_map(functions: list[FunctionSemanticRecord]) -> dict[str, dict[str, list[str]]]:
    """构建状态变量读写映射。"""

    access_map: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"readers": set(), "writers": set()}
    )
    for function in functions:
        fq_name = f"{function.contract_name}.{function.name}"
        for state_var in function.reads:
            access_map[state_var]["readers"].add(fq_name)
        for state_var in function.writes:
            access_map[state_var]["writers"].add(fq_name)

    return {
        state_var: {
            "readers": sorted(bucket["readers"]),
            "writers": sorted(bucket["writers"]),
        }
        for state_var, bucket in access_map.items()
    }


def _build_state_conflicts(state_access_map: dict[str, dict[str, list[str]]]) -> list[StateConflictRecord]:
    """构建函数间状态冲突图。"""

    conflicts: dict[tuple[str, str, str, str], StateConflictRecord] = {}
    for state_var, bucket in state_access_map.items():
        readers = bucket["readers"]
        writers = bucket["writers"]
        for writer in writers:
            for reader in readers:
                if writer == reader:
                    continue
                key = (state_var, writer, reader, "write-read")
                conflicts[key] = StateConflictRecord(
                    state_variable=state_var,
                    from_function=writer,
                    to_function=reader,
                    conflict_type="write-read",
                )
        for writer_a in writers:
            for writer_b in writers:
                if writer_a >= writer_b:
                    continue
                key = (state_var, writer_a, writer_b, "write-write")
                conflicts[key] = StateConflictRecord(
                    state_variable=state_var,
                    from_function=writer_a,
                    to_function=writer_b,
                    conflict_type="write-write",
                )
    return list(conflicts.values())


def parse_ast_semantics(file_paths: list[str]) -> AstSemanticSummary:
    """对一组 Solidity 文件做深 AST 语义分析。"""

    contract_names: list[str] = []
    contract_kinds: dict[str, str] = {}
    inheritance_edges: dict[str, list[str]] = defaultdict(list)
    state_variables: list[str] = []
    events: list[str] = []
    raw_functions: list[tuple[str, dict, dict[str, str], set[str]]] = []
    known_contract_names: set[str] = set()

    parsed_files = [parser.parse_file(file_path, loc=True) for file_path in file_paths]
    for ast in parsed_files:
        for child in ast.get("children", []):
            if child.get("type") == "ContractDefinition":
                known_contract_names.add(child.get("name", ""))

    for ast in parsed_files:
        for child in ast.get("children", []):
            if child.get("type") != "ContractDefinition":
                continue
            contract_name = child.get("name", "")
            contract_kind = child.get("kind", "contract")
            contract_names.append(contract_name)
            contract_kinds[contract_name] = contract_kind
            inheritance_edges[contract_name] = [
                base.get("baseName", {}).get("namePath", "")
                for base in child.get("baseContracts") or []
                if base.get("baseName", {}).get("namePath")
            ]

            contract_state_vars: set[str] = set()
            contract_refs = _collect_contract_reference_vars(child, known_contract_names)

            for sub_node in child.get("subNodes") or []:
                sub_type = sub_node.get("type")
                if sub_type == "StateVariableDeclaration":
                    for variable in sub_node.get("variables") or []:
                        variable_name = variable.get("name")
                        if variable_name:
                            state_variables.append(variable_name)
                            contract_state_vars.add(variable_name)
                elif sub_type == "EventDefinition":
                    event_name = sub_node.get("name")
                    if event_name:
                        events.append(event_name)
                elif sub_type == "FunctionDefinition":
                    raw_functions.append(
                        (contract_name, sub_node, dict(contract_refs), set(contract_state_vars))
                    )

    known_function_names = {
        function_node.get("name")
        for _contract_name, function_node, _contract_refs, _state_vars in raw_functions
        if function_node.get("name")
    }

    internal_call_edges: list[CallEdgeRecord] = []
    cross_contract_edges: list[CallEdgeRecord] = []
    functions = [
        _extract_function_semantics(
            contract_name=contract_name,
            function_node=function_node,
            known_function_names=known_function_names,
            contract_refs=contract_refs,
            known_contract_names=known_contract_names,
            state_vars=state_vars,
            internal_call_edges=internal_call_edges,
            cross_contract_edges=cross_contract_edges,
        )
        for contract_name, function_node, contract_refs, state_vars in raw_functions
    ]

    state_access_map = _build_state_access_map(functions)
    state_conflicts = _build_state_conflicts(state_access_map)
    public_entrypoints = sorted(
        f"{function.contract_name}.{function.name}"
        for function in functions
        if function.visibility in {"public", "external"}
    )
    write_after_external_functions = sorted(
        f"{function.contract_name}.{function.name}"
        for function in functions
        if function.external_call_then_state_write
    )

    return AstSemanticSummary(
        contract_names=contract_names,
        contract_kinds=contract_kinds,
        inheritance_edges=dict(inheritance_edges),
        state_variables=state_variables,
        events=events,
        public_entrypoints=public_entrypoints,
        state_access_map=state_access_map,
        internal_call_edges=internal_call_edges,
        cross_contract_call_edges=cross_contract_edges,
        state_conflicts=state_conflicts,
        write_after_external_functions=write_after_external_functions,
        functions=functions,
    )
