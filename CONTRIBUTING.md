# Contributing to Bug Bounty AI Agent

We love your input! We want to make contributing to this project as easy and transparent as possible.

## Development Process

1. Fork the repo and create your branch from `develop`
2. Install development dependencies: `pip install -e ".[dev]"`
3. Set up pre-commit hooks: `pre-commit install`
4. Make your changes
5. Run tests: `pytest tests/`
6. Run linting: `black agent/ && flake8 agent/`
7. Run security checks: `bandit -r agent/`
8. Submit a pull request

## Pull Request Guidelines

- Update the README.md with details of changes if needed
- Update the docs with any new functionality
- Add tests for new features
- Ensure all tests pass
- Follow existing code style

## Reporting Bugs

**Never report security vulnerabilities through public GitHub issues** - use security@bugbountyagent.com

For other bugs:
- Use the bug report template
- Include detailed steps to reproduce
- Include Python version and OS
- Include relevant logs

## Feature Requests

- Use the feature request template
- Explain why this feature would be useful
- Provide examples if possible

## Code Style

- We use Black for code formatting
- We use flake8 for linting
- We use mypy for type checking
- We use bandit for security checks

## License

By contributing, you agree that your contributions will be licensed under the MIT License.