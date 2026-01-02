"""
Medic Agent Learning Module

Outcome tracking, pattern analysis, and adaptive threshold adjustment.
Introduced in Phase 4.
"""

from learning.outcome_store import (
    OutcomeStore,
    SQLiteOutcomeStore,
    InMemoryOutcomeStore,
    ResurrectionOutcome,
    OutcomeType,
    FeedbackSource,
    OutcomeStatistics,
    create_outcome_store,
)
from learning.pattern_analyzer import (
    PatternAnalyzer,
    DetectedPattern,
    PatternType,
    PatternSeverity,
    ModuleProfile,
    AnalysisConfig,
    create_pattern_analyzer,
)
from learning.threshold_adapter import (
    ThresholdAdapter,
    ThresholdAdjustment,
    AdjustmentType,
    AdjustmentProposal,
    AdaptiveConfig,
    CurrentThresholds,
    create_threshold_adapter,
)
from learning.feedback import (
    FeedbackProcessor,
    AutomatedFeedbackCollector,
    Feedback,
    FeedbackType,
    FeedbackStats,
    create_feedback_processor,
    create_automated_collector,
)

__all__ = [
    # Outcome Store
    "OutcomeStore",
    "SQLiteOutcomeStore",
    "InMemoryOutcomeStore",
    "ResurrectionOutcome",
    "OutcomeType",
    "FeedbackSource",
    "OutcomeStatistics",
    "create_outcome_store",
    # Pattern Analyzer
    "PatternAnalyzer",
    "DetectedPattern",
    "PatternType",
    "PatternSeverity",
    "ModuleProfile",
    "AnalysisConfig",
    "create_pattern_analyzer",
    # Threshold Adapter
    "ThresholdAdapter",
    "ThresholdAdjustment",
    "AdjustmentType",
    "AdjustmentProposal",
    "AdaptiveConfig",
    "CurrentThresholds",
    "create_threshold_adapter",
    # Feedback
    "FeedbackProcessor",
    "AutomatedFeedbackCollector",
    "Feedback",
    "FeedbackType",
    "FeedbackStats",
    "create_feedback_processor",
    "create_automated_collector",
]
