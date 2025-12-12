#!/bin/bash

HOOK_DIR=".git/hooks"
PRE_PUSH="$HOOK_DIR/pre-push"

echo "Installing pre-push hook..."

# Create the hook file
cat > "$PRE_PUSH" <<EOF
#!/bin/bash

echo "Running tests before push..."

# Run go vet
go vet ./...

# Run all tests in the repository
go test ./... -v

# Capture the result
RESULT=\$?

if [ \$RESULT -ne 0 ]; then
    echo "Tests failed. Push aborted."
    exit 1
fi

echo "Tests passed. Pushing..."
exit 0
EOF

chmod +x "$PRE_PUSH"

echo "Hook installed successfully!"
