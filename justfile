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

# Show pre-build log
prebuild-log:
    if [ -f src/build-stamps/wasmtime_build.stamp ]; then cat src/build-stamps/wasmtime_build.stamp; else echo "stamp not found; run 'moon build src/main'"; exit 1; fi

# Generate type definition files
info:
    moon info

# Clean build artifacts
clean:
    moon clean

# Pre-release check
release-check: fmt info check test
