# Leaked Credentials Checker

A local-only software to check for leaked credentials. Currently only supports checking a password hash against a thin REST API.

Intended to be used with plugins like [LCC Keycloak](https://rechenknecht.net/mixxplorer/lcc/lcc-keycloak).

## Architecture

This software needs all password hashes downloaded as a file with one hash a line. Then, it can generate a xor filter, which is being used by the web API to check whether a particular hash is included in the leaked hash file provided. This check is done in a few microseconds.

## Usage

You can use a prepared filter from us or build the software yourself. For building, please see below.

We provide a [Docker image](./Dockerfile_filter), which contains the Have I been pwned filter as well as the web API binaries. It might incorporate more sources in future when they become available. You can run it like

```bash
docker run -it --rm -p 127.0.0.1:3000:3000 --name lcc-api dr.rechenknecht.net/mixxplorer/lcc/lcc:api-latest-all

# request API
curl 'http://localhost:3000/v1/hashes/check' -X POST -H 'Content-Type: application/json' --data-raw $'{\n"hash": "1000000A0E3B9F25FF41DE4B5A"\n}' -v
```

We also provide a much smaller image just containing the binaries:

```bash
docker run -it --rm -p 127.0.0.1:3000:3000 --name lcc-api dr.rechenknecht.net/mixxplorer/lcc/lcc:bin-latest
```

You can make use of the following tags per image:

* `api-v1-all` containing the latest API with support to the `v1` REST API.
* `api-latest-all` containing the latest API.
* `bin-v1` containing the binaries providing support to the `v1` REST API.
* `bin-latest` containing the latest binaries.

We re-build all images every week with the latest hashes. Therefore, please make sure to restart your API instance accordingly.

For a full list of available images, please see the [Container Registry](https://rechenknecht.net/mixxplorer/lcc/lcc/container_registry).

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
