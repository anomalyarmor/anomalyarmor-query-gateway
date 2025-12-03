# Contributing to AnomalyArmor Query Gateway

We welcome contributions! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/anomalyarmor-query-gateway.git`
3. Install development dependencies: `pip install -e ".[dev]"`
4. Create a branch: `git checkout -b feature/your-feature-name`

## Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install in development mode
pip install -e ".[dev]"

# Verify setup
pytest
ruff check src/ tests/
mypy src/
```

## Code Standards

### Style

- We use `ruff` for linting and formatting
- We use `mypy` for type checking with strict mode
- All code must pass CI checks

### Testing

- All new features must include tests
- Aim for >90% code coverage on new code
- Security-related code requires dedicated security tests

### Commits

Follow conventional commits:

```
<type>(<scope>): <subject>

Types: feat, fix, docs, style, refactor, test, chore
```

Examples:
- `feat(validator): add window function detection`
- `fix(parser): handle comments in subqueries`
- `test(dialects): add mysql system table tests`

## Pull Request Process

1. Ensure all tests pass: `pytest`
2. Ensure linting passes: `ruff check src/ tests/`
3. Ensure type checking passes: `mypy src/`
4. Update documentation if needed
5. Create PR with clear description

### PR Description Template

```markdown
## Summary
Brief description of changes

## Changes
- Change 1
- Change 2

## Testing
How was this tested?

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Type hints added
```

## Adding New Dialects

To add support for a new SQL dialect:

1. Create `src/anomalyarmor_query_gateway/dialects/your_dialect.py`
2. Implement `YourDialectRules(BaseDialectRules)`
3. Register in `dialects/__init__.py`
4. Add tests in `tests/dialects/test_your_dialect.py`
5. Update README with supported dialect

## Questions?

Open an issue with the `question` label or reach out to the maintainers.
