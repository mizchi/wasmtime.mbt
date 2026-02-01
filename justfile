# MoonBit Project Commands

# Default target (native for Wasmtime bindings)
target := "native"

# Default task: check and test
default: check test

# Format code
fmt:
    moon fmt

# Type check
check:
    moon check --deny-warn --target {{target}}

# Run tests
test:
    moon test --target {{target}} --release

# Update snapshot tests
test-update:
    moon test --update --target {{target}} --release

# Run main
run:
    moon run src/main --target {{target}}

# Generate type definition files
info:
    moon info

# Clean build artifacts
clean:
    moon clean

# Pre-release check
release-check: fmt info check test
