# Contributing to OSS Dependency Intelligence

Thank you for your interest in contributing to OSS Dependency Intelligence!

## Development Workflow

1. Fork the repository and clone your fork locally.
2. Create a dedicated feature branch (`git checkout -b feature/my-new-feature`).
3. Set up the local Python virtualenv and install dependencies (`pip install -r requirements.txt`).
4. Set up the frontend workspace (`cd apps/web && npm install`).
5. Ensure all automated tests pass (`PYTHONPATH=. pytest backend/tests -v`).
6. Build web assets (`cd apps/web && npm run build`).
7. Commit your changes and submit a Pull Request.

## Code Standards

- Backend: Python 3.11+, typed interfaces, explicit schemas, unit tests for all parsers and scoring rules.
- Frontend: TypeScript strict mode, clean components, Tailwind CSS styling.
