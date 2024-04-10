# Leaked Credentials Checker

A local-only software to check for leaked credentials. Currently only supports checking a password hash against a thin REST API.

## Architecture

This software needs all password hashes downloaded as a file with one hash a line. Then, it can generate a xor filter, which is being used by the web API to check whether a particular hash is included in the leaked hash file provided. This check is done in a few microseconds.

## Building

```bash
cargo build --release
```

It is important to build the release version of this software if you are dealing with larger filters or inputs as the performance is better by a factor of at least 10 when using the release build.

## Generating filter

This software support generating the filter with have I been pwned password hashes.

### Download HaveIBeenPwned password hashes

```bash
docker run -it --rm mcr.microsoft.com/dotnet/sdk /bin/bash
export PATH="$PATH:/root/.dotnet/tools"
dotnet tool install --global haveibeenpwned-downloader
haveibeenpwned-downloader pwnedpasswords
```

This will create the file `pwnedpasswords.txt`.

### Generate and test filter

`target/release/leaked-passwords-filter-tool pwnedpasswords.txt filter.bincode -b`

For generating the filter file for the full pwnedpasswords set, you need about 35 GB of memory. You can make use of swap pretty efficiently.

### Run web API

```bash
target/release/lcc-web-api -f filter.bincode
```

now, you can request it like `curl 'http://localhost:3000/v1/hashes/check' -X POST -H 'Content-Type: application/json' --data-raw $'{\n"hash": "1000000B0E6B3F21"\n}'`
