"""How much of a baseline a scan actually judged.

A violation count alone cannot answer "is this estate compliant?" — it only says
what the rules that ran found. When most rules could not run, "0 violations" and
"compliant" are different claims, and reporting the first as the second is how a
scan certifies an estate it never inspected.

Every surface that shows violations (CLI scan, report, web dashboard, MCP tools)
reads coverage from here rather than counting rows itself, so they cannot drift
into disagreeing about the same snapshot.
"""

from dataclasses import dataclass, field

import duckdb


@dataclass(frozen=True)
class Coverage:
    """Per-snapshot tally of which rules were able to judge."""

    evaluated: int = 0
    undetermined: int = 0
    #: ``(rule_id, reason)`` for rules that were not run, in stable id order —
    #: there is no severity here, because a rule that did not run has no finding
    #: to rank. Capped; see :attr:`undetermined_rules_truncated`.
    undetermined_rules: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    #: True when :attr:`undetermined_rules` is a page rather than the whole list.
    #:
    #: The count in :attr:`undetermined` is always complete, so the summary line
    #: stays honest either way — but a reader shown "16 of 20 could not be
    #: evaluated" beside a list of one would reasonably conclude the other
    #: fifteen were fine. Reachable by scanning one snapshot against several
    #: baselines.
    undetermined_rules_truncated: bool = False

    @property
    def total(self) -> int:
        return self.evaluated + self.undetermined

    @property
    def tracked(self) -> bool:
        """False for snapshots taken before outcomes were recorded."""
        return self.total > 0

    @property
    def complete(self) -> bool:
        """True only when every rule in the scan was able to judge.

        Requires ``tracked``. Without outcome rows there is nothing to conclude,
        and returning True there would announce full coverage for a scan that
        never measured any — the original false-compliance claim, one release
        later and harder to spot.
        """
        return self.tracked and self.undetermined == 0

    def summary_line(self) -> str:
        """One sentence for a human, or empty when there is nothing to warn about.

        Deliberately empty when coverage is complete: a banner on every clean
        scan trains people to skip it, and then it goes unread on the scan that
        matters.
        """
        if not self.tracked:
            return (
                "This snapshot predates coverage tracking — how many of its "
                "rules could actually be evaluated is unknown. Re-scan to find out."
            )
        if self.complete:
            return ""
        return (
            f"{self.undetermined} of {self.total} rules could not be evaluated "
            f"— no collector provides the data they check, so their result is "
            f"unknown, not compliant."
        )

    def as_dict(self) -> dict:
        return {
            "evaluated": self.evaluated,
            "undetermined": self.undetermined,
            "total": self.total,
            "tracked": self.tracked,
            "complete": self.complete,
            "undetermined_rules": [
                {"rule": rule_id, "reason": reason}
                for rule_id, reason in self.undetermined_rules
            ],
            "undetermined_rules_truncated": self.undetermined_rules_truncated,
        }


def coverage_for(twin, snapshot_id: str, *, rule_limit: int = 100) -> Coverage:
    """Tally rule outcomes for one snapshot.

    Returns an empty :class:`Coverage` for snapshots taken before outcomes were
    recorded. That is reported as ``total == 0`` rather than as full coverage —
    an older scan genuinely does not know how much it judged, and claiming it was
    complete would put the original false-compliance claim back, one release
    later and harder to see.
    """
    try:
        counts = dict(
            twin.conn.execute(
                "SELECT outcome, COUNT(*) FROM rule_outcome WHERE snapshot_id = ? "
                "GROUP BY outcome",
                [snapshot_id],
            ).fetchall()
        )
        rules = twin.conn.execute(
            "SELECT rule_id, reason FROM rule_outcome "
            "WHERE snapshot_id = ? AND outcome = 'undetermined' "
            "ORDER BY rule_id LIMIT ?",
            # One extra row is the cheapest way to know the list was cut without
            # a second COUNT — the surplus is dropped below.
            [snapshot_id, rule_limit + 1],
        ).fetchall()
    except duckdb.CatalogException:
        # The table does not exist: a database created before 1.9.0, opened
        # read-only. `Twin.open_readonly` skips schema init because DDL is a
        # write, so the web dashboard cannot self-heal the way the CLI does —
        # and every page that shows violations would 500 on a user's existing
        # database the moment they upgrade, before they run a new scan.
        #
        # A missing table is exactly what `tracked=False` describes: coverage
        # was never measured. Returning that is both accurate and the same
        # answer the CLI gives for such a snapshot.
        return Coverage()
    truncated = len(rules) > rule_limit
    return Coverage(
        evaluated=counts.get("evaluated", 0),
        undetermined=counts.get("undetermined", 0),
        undetermined_rules=tuple((r[0], r[1] or "") for r in rules[:rule_limit]),
        undetermined_rules_truncated=truncated,
    )
