# Contributing to Medic Agent

Thank you for your interest in contributing to Medic Agent! This document provides guidelines and information for contributors.

## Development Setup

### Prerequisites

- Python 3.11+
- Redis (for event bus testing)
- Docker (optional, for container testing)

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/kase1111-hash/medic-agent.git
cd medic-agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies (including dev dependencies)
pip install -r requirements.txt

# Set up pre-commit hooks (optional)
pip install pre-commit
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=core --cov=execution --cov=learning --cov-report=html

# Run specific test categories
pytest tests/unit/ -v          # Fast unit tests
pytest tests/security/ -v      # Security tests
pytest tests/integration/ -v   # Integration tests (requires Redis)
```

## Code Style

### Python Style Guide

- Follow [PEP 8](https://pep8.org/) style guidelines
- Use [Black](https://github.com/psf/black) for code formatting
- Use [isort](https://pycqa.github.io/isort/) for import sorting
- Use type hints for all function signatures

### Code Formatting

```bash
# Format code
black .
isort .

# Check formatting
black --check .
isort --check-only .

# Type checking
mypy core/ execution/ learning/ integration/
```

### Naming Conventions

- Classes: `PascalCase`
- Functions/methods: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private methods: `_leading_underscore`
- Module files: `snake_case.py`

## Pull Request Process

### Before Submitting

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the code style guidelines

3. **Add tests** for new functionality:
   - Unit tests in `tests/unit/`
   - Integration tests in `tests/integration/`
   - Security tests in `tests/security/` if applicable

4. **Run the test suite** and ensure all tests pass:
   ```bash
   pytest tests/ -v
   ```

5. **Update documentation** if needed:
   - Update docstrings
   - Update README.md if adding features
   - Update CHANGELOG.md with your changes

### Submitting a Pull Request

1. Push your branch to GitHub:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Open a Pull Request with:
   - Clear title describing the change
   - Description of what was changed and why
   - Reference to any related issues
   - Test plan describing how to verify the changes

3. Wait for CI checks to pass

4. Address any review feedback

### PR Title Format

Use conventional commit format:
- `feat: Add new feature`
- `fix: Fix bug in component`
- `docs: Update documentation`
- `test: Add/update tests`
- `refactor: Refactor code without changing behavior`
- `chore: Update dependencies/tooling`

## Architecture Guidelines

### Module Structure

```
medic-agent/
├── core/           # Core business logic
├── execution/      # Resurrection execution
├── interfaces/     # User interfaces (CLI, API)
├── learning/       # Adaptive learning system
├── integration/    # External integrations
├── config/         # Configuration files
└── tests/          # Test suite
```

### Adding New Components

1. **Abstract interfaces first**: Define abstract base classes in the appropriate module
2. **Implement concrete classes**: Create implementations following the interface
3. **Factory functions**: Add factory functions for component creation
4. **Configuration**: Add configuration options to `config/medic.yaml`
5. **Tests**: Write comprehensive tests

### Error Handling

- Use custom exceptions from `core/errors.py`
- Log errors with appropriate context
- Implement circuit breaker pattern for external services
- Add retry logic with exponential backoff

### Logging

- Use structured logging via `core/logger.py`
- Include trace IDs for correlation
- Log at appropriate levels:
  - `DEBUG`: Detailed debugging information
  - `INFO`: General operational information
  - `WARNING`: Unexpected but handled situations
  - `ERROR`: Errors that need attention

## Security Guidelines

### Secrets Handling

- **Never** commit secrets to the repository
- Use environment variables for sensitive configuration
- Document required secrets in `.env.example`

### Input Validation

- Validate all external input
- Use type hints and runtime validation
- Protect against injection attacks

### Dependencies

- Keep dependencies updated
- Review security advisories
- Use `pip-audit` to check for vulnerabilities

## Testing Guidelines

### Test Categories

| Category | Location | Purpose |
|----------|----------|---------|
| Unit | `tests/unit/` | Test individual components in isolation |
| Integration | `tests/integration/` | Test component interactions |
| Security | `tests/security/` | Test security controls |
| Performance | `tests/performance/` | Test performance characteristics |

### Writing Tests

- Use descriptive test names: `test_should_reject_invalid_input`
- Use fixtures for common setup
- Test edge cases and error conditions
- Aim for high coverage of critical paths

### Test Fixtures

Common fixtures are defined in `tests/conftest.py`:
- `sample_kill_report`: Standard kill report for testing
- `sample_siem_response`: Standard SIEM response
- `sample_config`: Default configuration

## Release Process

Releases are managed by maintainers following semantic versioning:

- **Major** (X.0.0): Breaking changes
- **Minor** (0.X.0): New features, backward compatible
- **Patch** (0.0.X): Bug fixes, backward compatible
- **Pre-release** (-alpha, -beta, -rc): Testing releases

## Getting Help

- **Issues**: Use GitHub Issues for bugs and feature requests
- **Discussions**: Use GitHub Discussions for questions

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

Thank you for contributing!
