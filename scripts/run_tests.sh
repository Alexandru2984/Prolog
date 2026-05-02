#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
swipl -q -s tests/run_tests.pl -t run_tests
