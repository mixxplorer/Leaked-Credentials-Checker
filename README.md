# Leaked Credentials Checker

A local-only software to check for leaked credentials. Currently only supports checking a password hash against a thin REST API.

Checks take less than one microsecond per hash, leading to an API response time well below 1ms.

Intended to be used with plugins like [LCC Keycloak](https://rechenknecht.net/mixxplorer/lcc/lcc-keycloak).

## Architecture

This software requires all password hashes to be downloaded as a file with one hash per line. Then, it can generate an XOR filter that is used by the web API to check whether a particular hash is included in the leaked hash file provided. This check is done in a few microseconds.

## Usage

You can use our pre-built filter or build the software yourself. For building, see the instructions below. To run with the pre-built filter, you will need memory equal to the filter size - currently about 10 GB.

We provide a [Docker image](./Dockerfile_filter) containing the Have I Been Pwned filter along with the web API binaries. More sources may be incorporated in the future as they become available. To run it, execute:

```bash
# Be aware of the security considerations below
docker run -it --rm -p 127.0.0.1:3000:3000 --name lcc-api dr.rechenknecht.net/mixxplorer/lcc/lcc/main:api-latest-all

# request API
curl 'http://localhost:3000/v1/hashes/check' -X POST -H 'Content-Type: application/json' --data-raw $'{\n"hash": "1000000A0E3B9F25FF41DE4B5A"\n}' -v

# To retrieve an OpenAPI spec of the API, go to http://localhost:3000/docs
```

We also provide a smaller image containing only the binaries:

```bash
docker run -it --rm -p 127.0.0.1:3000:3000 --name lcc-api dr.rechenknecht.net/mixxplorer/lcc/lcc/main:bin-latest
```

You can make use of the following tags per image:

* `api-v1-all` containing the latest API with support to the `v1` REST API.
* `api-latest-all` containing the latest API.
* `bin-v1` containing the binaries providing support to the `v1` REST API.
* `bin-latest` containing the latest binaries.

We re-build all images every week with the latest hashes. Therefore, please make sure to restart your API instance accordingly.

For a full list of available images, please see the [Container Registry](https://rechenknecht.net/mixxplorer/lcc/lcc/container_registry).

### Security considerations

This software is intended to work with password hashes. As some of the passwords are expected to be found in the XOR filter, it might be possible to retrieve the plain text password from the hash.

Therefore, we recommend the following deployment details:

* Only communicate with the API via secure means (run a TLS proxy in front of it, only use it via a VPN, etc.).
* Do not allow the lcc container to access the internet, it does not need it during normal operation. Don't forget DNS request.
* Do not allow the lcc container to access any other resource on the network beside answering connections to the API. The container will, under normal conditions, never start requests to other network resources.
* Update the container regularly, see also our [security policy](./SECURITY.md).

## Building

```bash
cargo build --release
```

It is important to build the release version of this software if you are dealing with larger filters or inputs as the performance is better by a factor of at least 10 when using the release build.

## Generating filter

This software supports generating filters using Have I Been Pwned password hashes.

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

After starting the API, you can request it like this: `curl 'http://localhost:3000/v1/hashes/check' -X POST -H 'Content-Type: application/json' --data-raw $'{\n"hash": "1000000B0E6B3F21"\n}'`

## License

This project is licensed under, at your option, either the [Apache 2 License](./LICENSE-APACHE) or the [MIT License](./LICENSE-MIT).

## Support development ❤️

The development is mainly funded by [Mixxplorer](https://mixxplorer.de). If you're able to support our work, please consider sponsoring us or encouraging your organization to have [Mixxplorer](https://mixxplorer.de) implement free software projects like this one.
