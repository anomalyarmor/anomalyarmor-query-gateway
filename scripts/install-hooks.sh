#!/bin/bash
# Install git hooks for anomalyarmor-query-gateway
# Run this after cloning the repo: ./scripts/install-hooks.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "Installing git hooks..."

# Create pre-commit hook
cat > "$HOOKS_DIR/pre-commit" << 'EOF'
#!/bin/bash
# Pre-commit hook for anomalyarmor-query-gateway
# Runs linting and type checking before allowing commits

set -e

echo "Running pre-commit checks..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track if any check fails
FAILED=0

# 1. Ruff linter
echo -e "\n${YELLOW}[1/3] Running ruff linter...${NC}"
if ruff check src/ tests/; then
    echo -e "${GREEN}✓ Ruff linter passed${NC}"
else
    echo -e "${RED}✗ Ruff linter failed${NC}"
    FAILED=1
fi

# 2. Ruff formatter check
echo -e "\n${YELLOW}[2/3] Running ruff format check...${NC}"
if ruff format --check src/ tests/; then
    echo -e "${GREEN}✓ Ruff format check passed${NC}"
else
    echo -e "${RED}✗ Ruff format check failed${NC}"
    echo -e "${YELLOW}  Run 'ruff format src/ tests/' to fix${NC}"
    FAILED=1
fi

# 3. Mypy type checking
echo -e "\n${YELLOW}[3/3] Running mypy type checker...${NC}"
if mypy src/; then
    echo -e "${GREEN}✓ Mypy type check passed${NC}"
else
    echo -e "${RED}✗ Mypy type check failed${NC}"
    FAILED=1
fi

# Summary
echo ""
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All pre-commit checks passed!${NC}"
    exit 0
else
    echo -e "${RED}Pre-commit checks failed. Fix the issues above before committing.${NC}"
    echo -e "${YELLOW}To bypass (not recommended): git commit --no-verify${NC}"
    exit 1
fi
EOF

chmod +x "$HOOKS_DIR/pre-commit"

echo "✓ Pre-commit hook installed"
echo ""
echo "The hook will run these checks before each commit:"
echo "  1. ruff check (linting)"
echo "  2. ruff format --check (formatting)"
echo "  3. mypy (type checking)"
echo ""
echo "To bypass the hook (not recommended): git commit --no-verify"
