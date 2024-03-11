# Leaked Credentials Checker

A local-only software to check for leaked credentials. Currently only supports checking a password hash against a thin REST API.

## Download HaveIBeenPwned password hashes

```bash
docker run -it --rm mcr.microsoft.com/dotnet/sdk /bin/bash
export PATH="$PATH:/root/.dotnet/tools"
dotnet tool install --global haveibeenpwned-downloader
haveibeenpwned-downloader pwnedpasswords
```

This will create the file `pwnedpasswords.txt`.
