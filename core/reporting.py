"""
Medic Agent Reporting

Generates daily summaries and reports in CSV and JSON formats.
Provides insights into decision patterns and system health.
"""

import csv
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict

from core.models import DecisionOutcome, RiskLevel
from core.log_decisions import DecisionLogger, DecisionRecord
from core.logger import get_logger

logger = get_logger("core.reporting")


@dataclass
class DailySummary:
    """Daily summary statistics."""

    date: str
    total_decisions: int
    outcomes: Dict[str, int]
    risk_levels: Dict[str, int]
    avg_risk_score: float
    avg_confidence: float
    modules_affected: List[str]
    top_kill_reasons: Dict[str, int]
    would_have_resurrected: int
    would_have_denied: int
    would_have_reviewed: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ModuleSummary:
    """Summary statistics for a specific module."""

    module: str
    total_kills: int
    decision_breakdown: Dict[str, int]
    avg_risk_score: float
    false_positive_likelihood: float
    recommendation: str


class ReportGenerator:
    """
    Generates reports from decision logs.

    Produces daily summaries, weekly analysis, and module-specific reports.
    """

    def __init__(
        self,
        decision_logger: DecisionLogger,
        reports_dir: str = "reports",
    ):
        self.decision_logger = decision_logger
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Report generator initialized", reports_dir=str(self.reports_dir))

    def generate_daily_summary(
        self,
        date: Optional[datetime] = None,
        save: bool = True,
    ) -> DailySummary:
        """
        Generate a daily summary report.

        Args:
            date: Date to summarize (defaults to today)
            save: Whether to save the report to disk

        Returns:
            DailySummary object
        """
        if date is None:
            date = datetime.utcnow()

        date_str = date.strftime("%Y-%m-%d")
        logger.info(f"Generating daily summary for {date_str}")

        records = self.decision_logger.get_decisions(date=date, limit=10000)

        if not records:
            summary = DailySummary(
                date=date_str,
                total_decisions=0,
                outcomes={},
                risk_levels={},
                avg_risk_score=0.0,
                avg_confidence=0.0,
                modules_affected=[],
                top_kill_reasons={},
                would_have_resurrected=0,
                would_have_denied=0,
                would_have_reviewed=0,
            )
        else:
            summary = self._compute_daily_summary(date_str, records)

        if save:
            self._save_daily_summary(summary)

        return summary

    def _compute_daily_summary(
        self,
        date_str: str,
        records: List[DecisionRecord],
    ) -> DailySummary:
        """Compute summary statistics from records."""
        outcomes: Dict[str, int] = {}
        risk_levels: Dict[str, int] = {}
        kill_reasons: Dict[str, int] = {}
        modules: set = set()

        total_risk = 0.0
        total_confidence = 0.0
        would_resurrect = 0
        would_deny = 0
        would_review = 0

        for record in records:
            # Count outcomes
            outcome = record.decision.outcome.value
            outcomes[outcome] = outcomes.get(outcome, 0) + 1

            # Count risk levels
            risk_level = record.decision.risk_level.value
            risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1

            # Count kill reasons
            reason = record.kill_report.kill_reason.value
            kill_reasons[reason] = kill_reasons.get(reason, 0) + 1

            # Track modules
            modules.add(record.kill_report.target_module)

            # Sum scores
            total_risk += record.decision.risk_score
            total_confidence += record.decision.confidence

            # Count what-would-happen
            if record.decision.outcome in (
                DecisionOutcome.APPROVE_AUTO,
                DecisionOutcome.APPROVE_MANUAL,
            ):
                would_resurrect += 1
            elif record.decision.outcome == DecisionOutcome.DENY:
                would_deny += 1
            else:
                would_review += 1

        total = len(records)

        # Sort kill reasons by count
        sorted_reasons = dict(
            sorted(kill_reasons.items(), key=lambda x: x[1], reverse=True)
        )

        return DailySummary(
            date=date_str,
            total_decisions=total,
            outcomes=outcomes,
            risk_levels=risk_levels,
            avg_risk_score=round(total_risk / total, 3),
            avg_confidence=round(total_confidence / total, 3),
            modules_affected=sorted(modules),
            top_kill_reasons=sorted_reasons,
            would_have_resurrected=would_resurrect,
            would_have_denied=would_deny,
            would_have_reviewed=would_review,
        )

    def _save_daily_summary(self, summary: DailySummary) -> None:
        """Save daily summary to JSON and CSV."""
        # Save JSON
        json_file = self.reports_dir / f"daily_summary_{summary.date}.json"
        with open(json_file, "w") as f:
            json.dump(summary.to_dict(), f, indent=2)
        logger.debug(f"Saved JSON summary: {json_file}")

        # Save CSV (append to monthly file)
        month = summary.date[:7]  # YYYY-MM
        csv_file = self.reports_dir / f"daily_summaries_{month}.csv"

        file_exists = csv_file.exists()
        with open(csv_file, "a", newline="") as f:
            writer = csv.writer(f)
            if not file_exists:
                # Write header
                writer.writerow([
                    "date",
                    "total_decisions",
                    "would_resurrect",
                    "would_deny",
                    "would_review",
                    "avg_risk_score",
                    "avg_confidence",
                    "modules_count",
                ])
            writer.writerow([
                summary.date,
                summary.total_decisions,
                summary.would_have_resurrected,
                summary.would_have_denied,
                summary.would_have_reviewed,
                summary.avg_risk_score,
                summary.avg_confidence,
                len(summary.modules_affected),
            ])
        logger.debug(f"Appended to CSV: {csv_file}")

    def generate_weekly_report(
        self,
        end_date: Optional[datetime] = None,
        save: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate a weekly analysis report.

        Args:
            end_date: End date of the week (defaults to today)
            save: Whether to save the report

        Returns:
            Dictionary with weekly analysis
        """
        if end_date is None:
            end_date = datetime.utcnow()

        start_date = end_date - timedelta(days=7)
        logger.info(
            f"Generating weekly report: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"
        )

        # Collect all records for the week
        all_records: List[DecisionRecord] = []
        daily_summaries: List[DailySummary] = []

        for i in range(7):
            date = end_date - timedelta(days=i)
            records = self.decision_logger.get_decisions(date=date, limit=10000)
            all_records.extend(records)

            if records:
                summary = self._compute_daily_summary(date.strftime("%Y-%m-%d"), records)
                daily_summaries.append(summary)

        if not all_records:
            report = {
                "period": {
                    "start": start_date.strftime("%Y-%m-%d"),
                    "end": end_date.strftime("%Y-%m-%d"),
                },
                "total_decisions": 0,
                "daily_summaries": [],
                "trends": {},
                "recommendations": ["No data available for this period"],
            }
        else:
            report = self._compute_weekly_report(
                start_date, end_date, all_records, daily_summaries
            )

        if save:
            self._save_weekly_report(report, end_date)

        return report

    def _compute_weekly_report(
        self,
        start_date: datetime,
        end_date: datetime,
        records: List[DecisionRecord],
        daily_summaries: List[DailySummary],
    ) -> Dict[str, Any]:
        """Compute weekly report from records and daily summaries."""
        # Aggregate statistics
        total_decisions = len(records)
        total_risk = sum(r.decision.risk_score for r in records)
        total_confidence = sum(r.decision.confidence for r in records)

        # Module analysis
        module_stats: Dict[str, Dict[str, Any]] = {}
        for record in records:
            module = record.kill_report.target_module
            if module not in module_stats:
                module_stats[module] = {
                    "count": 0,
                    "total_risk": 0.0,
                    "outcomes": {},
                }
            stats = module_stats[module]
            stats["count"] += 1
            stats["total_risk"] += record.decision.risk_score
            outcome = record.decision.outcome.value
            stats["outcomes"][outcome] = stats["outcomes"].get(outcome, 0) + 1

        # Calculate module summaries
        module_summaries = []
        for module, stats in module_stats.items():
            avg_risk = stats["total_risk"] / stats["count"]

            # Estimate false positive likelihood based on auto-approve rate
            auto_approve = stats["outcomes"].get("approve_auto", 0)
            fp_likelihood = auto_approve / stats["count"] if stats["count"] > 0 else 0

            recommendation = self._get_module_recommendation(avg_risk, fp_likelihood)

            module_summaries.append({
                "module": module,
                "total_kills": stats["count"],
                "avg_risk_score": round(avg_risk, 3),
                "false_positive_likelihood": round(fp_likelihood, 3),
                "decision_breakdown": stats["outcomes"],
                "recommendation": recommendation,
            })

        # Sort modules by kill count
        module_summaries.sort(key=lambda x: x["total_kills"], reverse=True)

        # Trend analysis
        trends = self._analyze_trends(daily_summaries)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            records, module_summaries, trends
        )

        return {
            "period": {
                "start": start_date.strftime("%Y-%m-%d"),
                "end": end_date.strftime("%Y-%m-%d"),
            },
            "total_decisions": total_decisions,
            "avg_risk_score": round(total_risk / total_decisions, 3),
            "avg_confidence": round(total_confidence / total_decisions, 3),
            "daily_summaries": [s.to_dict() for s in daily_summaries],
            "module_summaries": module_summaries,
            "trends": trends,
            "recommendations": recommendations,
        }

    def _get_module_recommendation(
        self,
        avg_risk: float,
        fp_likelihood: float,
    ) -> str:
        """Generate recommendation for a module based on its stats."""
        if avg_risk < 0.3 and fp_likelihood > 0.5:
            return "Consider adding to auto-approve list"
        elif avg_risk > 0.7:
            return "High risk - ensure manual review"
        elif fp_likelihood > 0.7:
            return "Likely false positive source - investigate"
        else:
            return "Normal - continue monitoring"

    def _analyze_trends(
        self,
        daily_summaries: List[DailySummary],
    ) -> Dict[str, Any]:
        """Analyze trends from daily summaries."""
        if len(daily_summaries) < 2:
            return {"status": "insufficient_data"}

        # Sort by date
        sorted_summaries = sorted(daily_summaries, key=lambda x: x.date)

        # Calculate trend direction
        first_half = sorted_summaries[: len(sorted_summaries) // 2]
        second_half = sorted_summaries[len(sorted_summaries) // 2:]

        first_avg_risk = sum(s.avg_risk_score for s in first_half) / len(first_half)
        second_avg_risk = sum(s.avg_risk_score for s in second_half) / len(second_half)

        first_count = sum(s.total_decisions for s in first_half)
        second_count = sum(s.total_decisions for s in second_half)

        risk_trend = "increasing" if second_avg_risk > first_avg_risk else "decreasing"
        volume_trend = "increasing" if second_count > first_count else "decreasing"

        return {
            "risk_trend": risk_trend,
            "risk_change": round(second_avg_risk - first_avg_risk, 3),
            "volume_trend": volume_trend,
            "volume_change": second_count - first_count,
            "busiest_day": max(sorted_summaries, key=lambda x: x.total_decisions).date,
            "quietest_day": min(sorted_summaries, key=lambda x: x.total_decisions).date,
        }

    def _generate_recommendations(
        self,
        records: List[DecisionRecord],
        module_summaries: List[Dict[str, Any]],
        trends: Dict[str, Any],
    ) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []

        # Check for high-volume modules
        if module_summaries:
            top_module = module_summaries[0]
            if top_module["total_kills"] > 10:
                recommendations.append(
                    f"Module '{top_module['module']}' has high kill volume "
                    f"({top_module['total_kills']} kills) - investigate root cause"
                )

        # Check for false positive patterns
        high_fp_modules = [
            m for m in module_summaries if m["false_positive_likelihood"] > 0.6
        ]
        if high_fp_modules:
            recommendations.append(
                f"{len(high_fp_modules)} module(s) show high false positive likelihood - "
                "consider adjusting Smith thresholds"
            )

        # Check risk trends
        if trends.get("risk_trend") == "increasing":
            recommendations.append(
                "Risk scores are trending upward - review security posture"
            )

        # Check for ready-for-auto modules
        auto_candidates = [
            m for m in module_summaries
            if m["avg_risk_score"] < 0.3 and m["total_kills"] >= 3
        ]
        if auto_candidates:
            recommendations.append(
                f"{len(auto_candidates)} module(s) may be candidates for auto-resurrection"
            )

        if not recommendations:
            recommendations.append("No significant issues detected - continue monitoring")

        return recommendations

    def _save_weekly_report(
        self,
        report: Dict[str, Any],
        end_date: datetime,
    ) -> None:
        """Save weekly report to disk."""
        week_str = end_date.strftime("%Y-W%W")
        json_file = self.reports_dir / f"weekly_report_{week_str}.json"

        with open(json_file, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Saved weekly report: {json_file}")

    def generate_module_report(
        self,
        module: str,
        days: int = 30,
    ) -> Dict[str, Any]:
        """
        Generate a detailed report for a specific module.

        Args:
            module: Module name
            days: Number of days of history

        Returns:
            Dictionary with module analysis
        """
        logger.info(f"Generating module report for '{module}'", days=days)

        records = self.decision_logger.get_module_history(module, days=days)

        if not records:
            return {
                "module": module,
                "period_days": days,
                "total_kills": 0,
                "message": "No data available for this module",
            }

        # Calculate statistics
        total_kills = len(records)
        total_risk = sum(r.decision.risk_score for r in records)
        total_confidence = sum(r.decision.confidence for r in records)

        outcome_counts: Dict[str, int] = {}
        reason_counts: Dict[str, int] = {}
        daily_counts: Dict[str, int] = {}

        for record in records:
            outcome = record.decision.outcome.value
            outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1

            reason = record.kill_report.kill_reason.value
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

            day = record.recorded_at.strftime("%Y-%m-%d")
            daily_counts[day] = daily_counts.get(day, 0) + 1

        # Assess stability
        auto_approve_rate = outcome_counts.get("approve_auto", 0) / total_kills
        deny_rate = outcome_counts.get("deny", 0) / total_kills

        if deny_rate > 0.5:
            stability = "unstable"
            recommendation = "Investigate recurring issues with this module"
        elif auto_approve_rate > 0.7:
            stability = "stable"
            recommendation = "Consider enabling auto-resurrection for this module"
        else:
            stability = "moderate"
            recommendation = "Continue monitoring before enabling auto-resurrection"

        return {
            "module": module,
            "period_days": days,
            "total_kills": total_kills,
            "avg_risk_score": round(total_risk / total_kills, 3),
            "avg_confidence": round(total_confidence / total_kills, 3),
            "outcome_breakdown": outcome_counts,
            "kill_reasons": reason_counts,
            "daily_activity": daily_counts,
            "stability_assessment": stability,
            "auto_approve_rate": round(auto_approve_rate, 3),
            "recommendation": recommendation,
        }


def create_report_generator(
    decision_logger: DecisionLogger,
    config: Dict[str, Any],
) -> ReportGenerator:
    """
    Factory function to create a report generator.

    Args:
        decision_logger: DecisionLogger instance
        config: Configuration dictionary

    Returns:
        Configured ReportGenerator instance
    """
    reports_dir = config.get("reports_dir", "reports")
    return ReportGenerator(decision_logger, reports_dir=reports_dir)
