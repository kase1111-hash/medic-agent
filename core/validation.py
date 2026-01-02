"""
Medic Agent Input Validation

Security-focused input validation for user-provided data.
Prevents injection attacks, path traversal, and resource exhaustion.
"""

import json
import re
from typing import Any, Dict

from core.logger import get_logger

logger = get_logger("core.validation")

# Configuration constants
MAX_MODULE_NAME_LENGTH = 255
MAX_INSTANCE_ID_LENGTH = 255
MAX_METADATA_SIZE_BYTES = 100_000  # 100KB
MAX_EVIDENCE_ITEMS = 100
MAX_EVIDENCE_ITEM_LENGTH = 10_000  # 10KB per evidence item
MAX_DEPENDENCY_COUNT = 100

# Regex patterns
MODULE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$')
INSTANCE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$')


class ValidationError(ValueError):
    """Raised when input validation fails."""
    pass


def validate_module_name(name: str, field_name: str = "module_name") -> str:
    """
    Validate a module name for security and correctness.

    Args:
        name: The module name to validate
        field_name: Name of the field (for error messages)

    Returns:
        The validated module name

    Raises:
        ValidationError: If validation fails

    Security:
        - Prevents path traversal (../, /, \\)
        - Prevents command injection
        - Enforces character whitelist
        - Enforces length limits
    """
    if not name:
        raise ValidationError(f"{field_name} cannot be empty")

    if not isinstance(name, str):
        raise ValidationError(f"{field_name} must be a string")

    # Check length
    if len(name) > MAX_MODULE_NAME_LENGTH:
        raise ValidationError(
            f"{field_name} too long: {len(name)} characters "
            f"(max {MAX_MODULE_NAME_LENGTH})"
        )

    # Check for path traversal
    if ".." in name or "/" in name or "\\" in name:
        logger.warning(f"Path traversal attempt detected in {field_name}: {name}")
        raise ValidationError(
            f"{field_name} contains invalid characters (path traversal detected)"
        )

    # Check for null bytes
    if "\x00" in name:
        logger.warning(f"Null byte detected in {field_name}: {name}")
        raise ValidationError(f"{field_name} contains null bytes")

    # Validate against pattern (alphanumeric, underscore, hyphen, dot)
    if not MODULE_NAME_PATTERN.match(name):
        logger.warning(f"Invalid {field_name} pattern: {name}")
        raise ValidationError(
            f"{field_name} must start with alphanumeric and contain only "
            "alphanumeric, underscore, hyphen, or dot characters"
        )

    return name


def validate_instance_id(instance_id: str, field_name: str = "instance_id") -> str:
    """
    Validate an instance ID for security and correctness.

    Args:
        instance_id: The instance ID to validate
        field_name: Name of the field (for error messages)

    Returns:
        The validated instance ID

    Raises:
        ValidationError: If validation fails

    Security:
        - Prevents path traversal
        - Prevents command injection
        - Enforces character whitelist
        - Enforces length limits
    """
    if not instance_id:
        raise ValidationError(f"{field_name} cannot be empty")

    if not isinstance(instance_id, str):
        raise ValidationError(f"{field_name} must be a string")

    # Check length
    if len(instance_id) > MAX_INSTANCE_ID_LENGTH:
        raise ValidationError(
            f"{field_name} too long: {len(instance_id)} characters "
            f"(max {MAX_INSTANCE_ID_LENGTH})"
        )

    # Check for path traversal
    if ".." in instance_id or "/" in instance_id or "\\" in instance_id:
        logger.warning(f"Path traversal attempt in {field_name}: {instance_id}")
        raise ValidationError(
            f"{field_name} contains invalid characters (path traversal detected)"
        )

    # Check for null bytes
    if "\x00" in instance_id:
        logger.warning(f"Null byte detected in {field_name}: {instance_id}")
        raise ValidationError(f"{field_name} contains null bytes")

    # Validate against pattern
    if not INSTANCE_ID_PATTERN.match(instance_id):
        logger.warning(f"Invalid {field_name} pattern: {instance_id}")
        raise ValidationError(
            f"{field_name} must start with alphanumeric and contain only "
            "alphanumeric, underscore, hyphen, or dot characters"
        )

    return instance_id


def validate_metadata(metadata: Dict[str, Any], field_name: str = "metadata") -> Dict[str, Any]:
    """
    Validate metadata dictionary for size and structure.

    Args:
        metadata: The metadata dictionary to validate
        field_name: Name of the field (for error messages)

    Returns:
        The validated metadata

    Raises:
        ValidationError: If validation fails

    Security:
        - Prevents resource exhaustion via large metadata
        - Enforces serialization limits
    """
    if not isinstance(metadata, dict):
        raise ValidationError(f"{field_name} must be a dictionary")

    # Check if serializable
    try:
        serialized = json.dumps(metadata)
    except (TypeError, ValueError) as e:
        logger.warning(f"Non-serializable {field_name}: {e}")
        raise ValidationError(f"{field_name} must be JSON-serializable: {e}")

    # Check size
    size_bytes = len(serialized.encode('utf-8'))
    if size_bytes > MAX_METADATA_SIZE_BYTES:
        logger.warning(
            f"Oversized {field_name}: {size_bytes} bytes "
            f"(max {MAX_METADATA_SIZE_BYTES})"
        )
        raise ValidationError(
            f"{field_name} too large: {size_bytes} bytes "
            f"(max {MAX_METADATA_SIZE_BYTES})"
        )

    return metadata


def validate_evidence_list(evidence: list, field_name: str = "evidence") -> list:
    """
    Validate evidence list for size and content.

    Args:
        evidence: The evidence list to validate
        field_name: Name of the field (for error messages)

    Returns:
        The validated evidence list

    Raises:
        ValidationError: If validation fails

    Security:
        - Prevents resource exhaustion via large evidence
        - Enforces item count and size limits
    """
    if not isinstance(evidence, list):
        raise ValidationError(f"{field_name} must be a list")

    # Check item count
    if len(evidence) > MAX_EVIDENCE_ITEMS:
        logger.warning(
            f"Too many {field_name} items: {len(evidence)} "
            f"(max {MAX_EVIDENCE_ITEMS})"
        )
        raise ValidationError(
            f"{field_name} has too many items: {len(evidence)} "
            f"(max {MAX_EVIDENCE_ITEMS})"
        )

    # Check each item
    for i, item in enumerate(evidence):
        if not isinstance(item, str):
            raise ValidationError(
                f"{field_name}[{i}] must be a string, got {type(item).__name__}"
            )

        if len(item) > MAX_EVIDENCE_ITEM_LENGTH:
            logger.warning(
                f"{field_name}[{i}] too long: {len(item)} chars "
                f"(max {MAX_EVIDENCE_ITEM_LENGTH})"
            )
            raise ValidationError(
                f"{field_name}[{i}] too long: {len(item)} characters "
                f"(max {MAX_EVIDENCE_ITEM_LENGTH})"
            )

    return evidence


def validate_dependency_list(dependencies: list, field_name: str = "dependencies") -> list:
    """
    Validate dependency list.

    Args:
        dependencies: The dependency list to validate
        field_name: Name of the field (for error messages)

    Returns:
        The validated dependency list

    Raises:
        ValidationError: If validation fails

    Security:
        - Prevents resource exhaustion via large dependency lists
        - Validates each dependency as a module name
    """
    if not isinstance(dependencies, list):
        raise ValidationError(f"{field_name} must be a list")

    # Check item count
    if len(dependencies) > MAX_DEPENDENCY_COUNT:
        logger.warning(
            f"Too many {field_name}: {len(dependencies)} "
            f"(max {MAX_DEPENDENCY_COUNT})"
        )
        raise ValidationError(
            f"{field_name} has too many items: {len(dependencies)} "
            f"(max {MAX_DEPENDENCY_COUNT})"
        )

    # Validate each dependency as a module name
    validated = []
    for i, dep in enumerate(dependencies):
        if not isinstance(dep, str):
            raise ValidationError(
                f"{field_name}[{i}] must be a string, got {type(dep).__name__}"
            )

        try:
            validated_dep = validate_module_name(dep, f"{field_name}[{i}]")
            validated.append(validated_dep)
        except ValidationError as e:
            # Re-raise with context
            raise ValidationError(f"Invalid dependency at index {i}: {e}")

    return validated


def validate_confidence_score(score: float, field_name: str = "confidence_score") -> float:
    """
    Validate a confidence score.

    Args:
        score: The score to validate (should be 0.0-1.0)
        field_name: Name of the field (for error messages)

    Returns:
        The validated score

    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(score, (int, float)):
        raise ValidationError(f"{field_name} must be a number")

    if not 0.0 <= score <= 1.0:
        raise ValidationError(
            f"{field_name} must be between 0.0 and 1.0, got {score}"
        )

    return float(score)


def sanitize_string_for_logs(value: str, max_length: int = 100) -> str:
    """
    Sanitize a string for safe logging.

    Args:
        value: The string to sanitize
        max_length: Maximum length before truncation

    Returns:
        Sanitized string safe for logging
    """
    if not isinstance(value, str):
        return str(value)

    # Remove control characters except newline and tab
    sanitized = ''.join(
        char if char.isprintable() or char in '\n\t' else '?'
        for char in value
    )

    # Truncate if too long
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."

    return sanitized
