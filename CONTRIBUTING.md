# Contributing

Thanks for taking the time. This document is the contract for whoever writes code here —
the `README.md` is the contract for whoever uses the package.

## Before you open a PR

One command has to be green:

```bash
./scripts/verify.sh
```

It is the same script the release runs, minus tag, push and publish: dependencies, README
version pin, analyze, the test suite on the VM, the test suite on Chrome, the runnable
example, the examples inside the `///` docs, `dart doc` with zero warnings, the publish
dry-run, and a pana score of 160/160. If it passes locally it passes in CI, because CI runs
that file and nothing else.

Budget around 15 minutes: the Chrome suite alone takes about 10 of them, for the reason
below. The script needs network — it asks pub.dev which pana version to use — and a Dart SDK
at or above the floor declared in `pubspec.yaml`. Running it changes your globally activated
pana version, since pub.dev always scores with the newest one.

## What CI checks

Two jobs, both on every pull request:

- **Verify** — `./scripts/verify.sh` on the current stable Dart.
- **Floor** — analyze and test on the **lowest** Dart the package supports, read straight
  from `pubspec.yaml`. It earns less here than in a Flutter package: the Dart SDK annotates
  new APIs with `@Since`, so an analyzer running on a newer SDK already warns and the gate
  already fails. What it still catches is real — an SDK API that carries no annotation,
  dependency resolution at the floor, and runtime behavior — and it costs about two minutes,
  so it stays.

Raise the floor in `pubspec.yaml` and the job follows on its own; the version is never
hardcoded in the workflow.

### Why the Chrome suite runs with `-j 1`

The web platform has no isolates, so RSA key generation runs on the page thread and blocks
it. With the default parallelism the suites compete for Chrome's worker slots and fail to
load at random. Sequential is slower and it is the only reliable setting.

## Conventions

- **No `//` comments.** A fact that needs recording goes in the commit message, in this
  document, or in a test. Analyzer directives (`// ignore:`) are not comments and may stay.
- **`///` dartdoc is mandatory on every public member**, in English, with a runnable example.
  `public_member_api_docs` is enforced, and `scripts/verify_doc_examples.sh` compiles every
  ```dart fence found in `lib/`. A fence must stand on its own: declare the variables it
  uses, and never lean on state the reader cannot see.
- **`lib/`, `test/` and `example/` stay web-clean.** No `dart:io`, `dart:ffi` or `dart:html`,
  and no direct `dart:isolate` import in algorithm code — key generation routes through
  `runOffThread` in `lib/src/core/platform.dart`, which resolves to `Isolate.run` on the VM
  and to synchronous execution on the web. `pubspec.yaml` declares no `platforms:` block on
  purpose: pana detects the support surface from the imports, and a hand-written list would
  only drift.
- **No foreign exception escapes the public API.** Wrap whatever a dependency throws — a
  `FormatException` from `base64Decode`, an `ArgumentError` from PointyCastle — into the
  matching `FortisException` subtype, at the boundary where it happens.
- **Behavior changes ship with their test.** Bug fixes start red: write the failing test
  first, watch it fail for the right reason, then fix.
- **A public-API change updates README, CHANGELOG and `example/example.dart` in the same
  commit.**
- **Commits are conventional and lowercase**: `feat:`, `fix:`, `chore:`, `docs:`. No body,
  no co-author trailers.

## Releasing

Releases are cut by the maintainer, from the default branch, with `./scripts/release.sh`.
Nothing publishes from CI.
