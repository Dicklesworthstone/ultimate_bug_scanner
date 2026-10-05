"""Finite taint facts and a deterministic forward dataflow solver (D6).

Frontends own syntax, bindings and API semantics. Evidence is deliberately not
part of lattice equality: recursive call paths must not keep an otherwise
stable analysis alive. A limit is an analysis error, never a clean answer.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace
from typing import Callable, Mapping


class AnalysisLimit(ValueError):
    """The bounded analysis could not finish; callers must report failure."""


@dataclass
class Budget:
    remaining: int = 500_000

    def spend(self, amount: int = 1) -> None:
        self.remaining -= amount
        if self.remaining < 0:
            raise AnalysisLimit("Taint dataflow work limit exceeded; analysis is incomplete")


@dataclass(frozen=True, order=True)
class Step:
    path: str
    line: int
    column: int
    kind: str
    label: str

    def record(self) -> dict:
        return dict(path=self.path, line=self.line, col=self.column,
                    kind=self.kind, label=self.label)


@dataclass(frozen=True)
class Trace:
    kind: str
    key: tuple
    tags: frozenset[str] = frozenset()
    removed_tags: frozenset[str] = frozenset()
    evidence: tuple[Step, ...] = field(default=(), compare=False)


Fact = frozenset[Trace]
CLEAN: Fact = frozenset()
State = dict[str, Fact]


def join(*facts: Fact) -> Fact:
    """Union with a deterministic, shortest witness for each semantic fact."""
    result: dict[Trace, Trace] = {}
    for fact in facts:
        for trace in fact:
            previous = result.get(trace)
            if previous is None or (len(trace.evidence), trace.evidence) < (len(previous.evidence), previous.evidence):
                result[trace] = trace
    return frozenset(result.values())


def advance(fact: Fact, step: Step) -> Fact:
    output = []
    for trace in fact:
        evidence = trace.evidence
        if not evidence or evidence[-1] != step:
            evidence += (step,)
        if len(evidence) > 12:
            evidence = (evidence[0], *evidence[-11:])
        output.append(replace(trace, evidence=evidence))
    return frozenset(output)


def retag(fact: Fact, *, add: frozenset[str] = frozenset(), remove: frozenset[str] = frozenset()) -> Fact:
    return join(frozenset(replace(trace, tags=(trace.tags - remove) | add,
                                  removed_tags=(trace.removed_tags | remove) - add) for trace in fact))


def substitute(fact: Fact, parameters: Mapping[tuple, Fact], call: Step) -> Fact:
    """Instantiate a summary in one caller, without sharing its local state."""
    output = CLEAN
    for trace in sorted(fact, key=lambda item: (item.kind, item.key, sorted(item.tags))):
        if trace.kind != "parameter":
            output = join(output, advance(frozenset({trace}), call))
            continue
        actual = parameters.get(trace.key, CLEAN)
        actual = retag(actual, add=trace.tags, remove=trace.removed_tags)
        actual = advance(actual, call)
        # Preserve the callee's operations as well as the caller's source.
        for step in trace.evidence:
            if step.kind != "parameter":
                actual = advance(actual, step)
        output = join(output, actual)
    return output


def join_states(*states: State) -> State:
    result: State = {}
    for state in states:
        for binding, fact in state.items():
            value = join(result.get(binding, CLEAN), fact)
            if value:
                result[binding] = value
    return result


def solve(entry: int, initial: State, edges: Mapping[int, tuple[int, ...]],
          transfer: Callable[[int, State], State], budget: Budget) -> dict[int, State]:
    """Least forward fixpoint over reachable nodes, including empty states.

    Assignments may strongly replace a binding: transfer functions need to be
    monotone in their *input*, not inflationary on each variable's old value.
    Only joins accumulate facts. Returning no outgoing edges models termination.
    """
    incoming = {entry: dict(initial)}
    pending = deque([entry])
    queued = {entry}
    while pending:
        budget.spend()
        node = pending.popleft()
        queued.remove(node)
        output = transfer(node, dict(incoming[node]))
        for successor in edges.get(node, ()):
            old = incoming.get(successor)
            merged = dict(output) if old is None else join_states(old, output)
            if old is None or old != merged:
                incoming[successor] = merged
                if successor not in queued:
                    pending.append(successor)
                    queued.add(successor)
    return incoming
