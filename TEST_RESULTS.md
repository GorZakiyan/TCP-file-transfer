# Actual results — 2026-11-06

## Environment checks performed

This delivery was prepared on Windows. The following commands were actually run:

* `wsl.exe --list --quiet` and `wsl.exe --status`: failed with
  `Access is denied`, `Wsl/E_ACCESSDENIED`.
* Compiler discovery: no `gcc` or `clang` command was available.
* `docker info --format '{{.OSType}}'`: failed because the Docker Linux engine
  named pipe `dockerDesktopLinuxEngine` did not exist. Launching the installed
  Docker Desktop application did not make that engine available.

## Build and integration status

**NOT EXECUTED.** No usable Linux build/runtime was available in this environment.
The source has been reviewed, but it has not been compiled here. No successful
file comparison, cryptographic rejection, interruption test, or test pass is
claimed. The project must be built and its integration suite run on Linux before
it can be regarded as verified working software.

## Source review follow-up

A manual source review was completed after the initial delivery. The following
changes were made; they are review findings/fixes, not executed test results:

* Interrupted connect now polls for completion and checks SO_ERROR, rather than
  repeating connect on a socket whose connection may already be in progress.
* Listener uses Linux mkstemps to create an exclusive mode-0600 `.part` file
  directly, removing the intermediate temporary-file rename.
* GCM payload output length is reset after AAD, zero-length END skips the payload
  update explicitly, and returned payload length is checked.
* Encryption helper is named crypt_frame to avoid collision with Linux crypt().
* Socket option failure is checked. Listening readiness is reported so tests
  can wait for readiness rather than depending on fixed startup sleeps.
* Pending tests now also cover 1/1023/1024/1025-byte boundaries, altered salt,
  reordered frames and duplicated frames.

Review covered byte order, bounds, per-frame nonce/counter use, tag handling,
authenticated END, spool-before-forwarding, empty files, key-file size checks,
sample creation, error exits and listener cleanup/rename ordering. No additional
correctness issue was found in that review. Compilation and runtime validation
remain pending; review is not proof that the program is free of bugs.

References checked: OpenSSL EVP authenticated encryption documentation
<https://docs.openssl.org/3.0/man3/EVP_EncryptInit/>.

## Reproduce the requested verification (Linux)

After installing the prerequisites in README.md, run:

```sh
make clean
make
make test 2>&1 | tee test-run.log
```

The suite prints a PASS line only after its assertions pass, and finally prints
`ALL TESTS PASSED` only after completing every case. It uses real C executables,
temporary files and localhost TCP sockets. All temporary test keys are randomly
generated and removed afterward. `test-run.log` is the actual result to retain.
When capturing the status through a pipe, use Bash `set -o pipefail` beforehand.

Expected coverage (pending execution): text, binary, empty, sample creation,
wrong key, ciphertext modification, length modification, END tag modification,
missing END, partial encrypted frame/salt, interrupted plaintext on both links,
partial plaintext header/payload, oversized plaintext length, preservation of
prior output, partial-file cleanup and rejection of incorrect key lengths.
