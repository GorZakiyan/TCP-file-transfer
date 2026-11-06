# Four-process file transfer (Linux / C / OpenSSL)

Sender → Encoder → Decoder → Listener. Four separate executables, each handles
one transfer and exits. All links use IPv4 TCP. Only the middle link is encrypted.

## Build

On Debian/Ubuntu Linux (including an existing WSL Linux installation):

```sh
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev openssl python3
make
```

Generate a private, raw 32-byte shared key in the project directory:

```sh
(umask 077; openssl rand -out transfer.key 32)
chmod 600 transfer.key
```

Use the same key file for encoder and decoder. Never commit or print it.
`*.key` is ignored by Git; if you choose another filename, add it to `.gitignore`.
The programs reject files shorter or longer than exactly 32 bytes.

## Run (four separate terminals, same directory)

Start these in the order shown. The listening processes wait for a connection.

Terminal 1:

```sh
./listener 127.0.0.1 5003 output.bin
```

Terminal 2:

```sh
./decoder 127.0.0.1 5002 127.0.0.1 5003 transfer.key
```

Terminal 3:

```sh
./encoder 127.0.0.1 5001 127.0.0.1 5002 transfer.key
```

Terminal 4:

```sh
./sender input.bin 127.0.0.1 5001
cmp input.bin output.bin && echo 'Files match'
```

If `input.bin` does not exist, sender creates a small sample there. Its parent
directory must already exist. Existing input files are read without modification.
Text, binary and zero-byte files work identically. Change any file path, IPv4
address or port through the arguments above. Quote paths containing spaces.
Encoder/decoder arguments: `BIND_IP BIND_PORT DEST_IP DEST_PORT KEY_FILE`.
Network namespaces are optional and unnecessary for this localhost demonstration.
If using namespaces, provide routing and reachable addresses yourself.

## Protocol and failure handling

The two plaintext links use a four-byte unsigned big-endian length followed by
that many bytes (1–1024); a zero length is explicit END. EOF before END fails.

Encoder sends an eight-byte random per-transfer salt, followed by encrypted
frames: four-byte big-endian plaintext length, ciphertext of that length, and a
16-byte AES-256-GCM authentication tag. The 12-byte nonce is salt followed by
the four-byte big-endian frame counter, starting at zero. Length bytes are AAD.
An encrypted zero-length frame with its own tag is END. Both peers reserve the
last counter value for END and reject further data rather than overflow. The
maximum transfer is `(2^32 - 1) * 1024` bytes with full-size frames.

Decoder checks every frame and END before connecting to listener. It spools
plaintext in a private automatically removed temporary file, so memory use stays
small; sufficient temporary disk space is necessary. Authentication failure,
truncation, invalid lengths and missing END terminate with nonzero status.

Listener writes to a unique adjacent `OUTPUT.<random>.part` file, then closes
and renames it to OUTPUT after END. On a detected error it removes the temporary
file and preserves previous output. Rename is atomic on the normal Linux local
filesystem. The containing output directory must be trusted and writable.
Socket loops handle partial reads/writes and EINTR; interrupted connect waits
for completion with poll and checks SO_ERROR. SIGPIPE is ignored so broken
connections become reported failures. Progress is not printed, and keys are
never printed. Readiness and errors go to stderr; success exits 0, failure exits nonzero.

## Security boundaries and limitations

* Sender→encoder and decoder→listener carry **plaintext**. Keep them on localhost
  or trusted networks. Those links provide framing, not authentication: a hostile
  peer can inject data or send a fake completion marker.
* An entire previously captured encrypted transfer can be replayed successfully.
  There is no persistent replay cache or freshness handshake. Counter-based
  nonces detect reordered/duplicated frames within a transfer, not whole replay.
* The random salt is 64 bits. Across many transfers with one key, collisions
  follow the birthday bound; a repeated salt repeats nonces and undermines GCM.
  Rotate keys and do not use this simple demonstration for high-volume service.
* There is no final delivery acknowledgement. Sender success means its local
  send completed, not that decoder authenticated or listener saved the file.
  Check all four exit statuses and compare files when verifying delivery.
* No retries, concurrency, timeouts, peer identity, key exchange, size quotas or
  production service hardening. A stalled peer can block; an attacker can consume
  spool disk. Stop waiting processes manually after an upstream rejection.
* Detected errors clean up listener partial files. Forced termination, power loss
  or a crash can leave `.part` files. No fsync/directory sync: rename is not a
  guarantee of survival across power loss. Ignore trailing bytes after END;
  each connection carries exactly one application transfer.

## Tests

```sh
make test
```

The Python standard-library integration runner starts the actual four programs
and compares bytes for text, binary, empty and automatically created sample
files. It captures a real encrypted stream and verifies rejection of wrong keys,
modified ciphertext, modified length AAD, modified END tag, missing END, partial
frames and partial salts, with no downstream connection on authentication failure.
It also tests truncated plaintext on both links, partial headers/payloads and
oversized frames, checks nonzero exit statuses, verifies existing output is
preserved and checks that detected failures leave no `.part` files.
See TEST_RESULTS.md for actual execution status in the delivery environment.
