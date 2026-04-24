#!/bin/bash
set -e

TOTAL_STEPS=8
STEP=0
step() {
  STEP=$((STEP + 1))
  echo
  echo "[$STEP/$TOTAL_STEPS] $1"
}

step "Installing dependencies"
dart pub get

step "Running tests"
dart test

step "Running tests (Chrome / web)"
# -j 1: web has no isolates, so RSA key-gen blocks the page thread.
# Running suites in parallel (default) exhausts Chrome worker slots and
# causes random suite-loading failures. Sequential is slower (~10 min)
# but reliable.
dart test -p chrome -j 1

step "Running example"
dart run example/example.dart

step "Validating package (dry-run)"
dart pub publish --dry-run

step "Running pana (pub.dev score)"
PANA_OUT=$(pana --no-warning . | tee /dev/stderr)
if ! grep -q "Points: 160/160" <<<"$PANA_OUT"; then
  echo
  echo "❌ Aborting release: pana score is below 160/160. Fix the issues above."
  exit 1
fi

VERSION=$(grep '^version:' pubspec.yaml | awk '{print $2}')

step "Creating tag v$VERSION"
if git rev-parse "v$VERSION" >/dev/null 2>&1; then
  echo "Tag v$VERSION already exists, skipping"
else
  git tag "v$VERSION"
fi

step "Pushing"
git push origin master
git push --tags

step "Publishing to pub.dev"
dart pub publish --force

echo
echo "🎉 Done! Published v$VERSION"