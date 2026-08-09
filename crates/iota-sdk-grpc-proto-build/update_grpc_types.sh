#!/bin/bash
# Copyright (c) 2026 IOTA Stiftung
# Modified by Mono Labs for the Monolythium IOTA Rust SDK, 2026.
# SPDX-License-Identifier: Apache-2.0
#
# Update gRPC protobuf types.
SCRIPT_PATH=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
ROOT="$SCRIPT_DIR/.."
GENERATED_DIR="$ROOT/iota-sdk-grpc-types/src/proto/generated"

pushd "$ROOT" >/dev/null || exit 1

function cleanup() {
    popd >/dev/null || true
}

trap cleanup EXIT

echo "Using $(protoc --version)"

rm -Rf "$GENERATED_DIR"
mkdir -p "$GENERATED_DIR"
cargo run -p iota-sdk-grpc-proto-build
exit_code=$?

if [ $exit_code -ne 0 ] && [ $exit_code -ne 2 ]; then
    echo "Error: Failed to generate protobuf files (exit code: $exit_code)"
    exit $exit_code
fi

# Checkpoint authentication is a Monolythium protocol extension. Keep its
# generated artifacts compliant with the fork's Apache modification-notice
# policy without rewriting unrelated generated files.
mono_notice='// Modified by Mono Labs for the Monolythium IOTA Rust SDK, 2026.'
for generated_file in \
    "$GENERATED_DIR/iota.grpc.v1.checkpoint.rs" \
    "$GENERATED_DIR/iota.grpc.v1.checkpoint.field_info.rs" \
    "$GENERATED_DIR/iota.grpc.v1.checkpoint.accessors.rs"; do
    if [ ! -f "$generated_file" ]; then
        echo "Error: Expected generated checkpoint artifact is missing: $generated_file"
        exit 1
    fi
    python3 - "$generated_file" "$mono_notice" <<'PYTHON'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
notice = sys.argv[2]
content = path.read_text(encoding="utf-8")
marker = "// Modifications Copyright (c) 2026 IOTA Stiftung\n"
if notice not in content:
    if marker not in content:
        raise SystemExit(f"IOTA modification notice missing from {path}")
    path.write_text(content.replace(marker, marker + notice + "\n", 1), encoding="utf-8")
PYTHON
    python_status=$?
    if [ $python_status -ne 0 ]; then
        echo "Error: Failed to add modification notice to: $generated_file"
        exit $python_status
    fi
    if ! grep -Fq "$mono_notice" "$generated_file"; then
        echo "Error: Failed to add modification notice to: $generated_file"
        exit 1
    fi
done

if [ $exit_code -eq 2 ]; then
    if ! git diff --quiet -- "$GENERATED_DIR"; then
        echo "Warning: Generated protobuf files have uncommitted changes."
        echo "The generation completed successfully, but you should commit the changes."
    fi
fi
