# Signet Docker Build

## Building the image

From the repository root:

```sh
make docker-image
```

This tags `signet:latest` and `signet:<version>`. The build uses only the vendored
dependencies, and `.dockerignore` keeps everything else in the tree out of it. A plain
`docker build -f contrib/packaging/docker/Dockerfile .` works too, but the binary then
reports its hash and build time as `unknown`.

`make test-docker` builds the image and tests everything below, including mail against
a fake relay on an internal Docker network. It needs `:8080` free and
`contrib/packaging/docker/config.yaml` absent.

## Running it

`signet serve` refuses to start until `cookie_secret` is set, so make a configuration
first:

```sh
cp config/example.yaml contrib/packaging/docker/config.yaml
# Set cookie_secret to the output of: openssl rand -hex 32
vi contrib/packaging/docker/config.yaml
```

The file holds that secret, and the container runs as uid 1001, so give it to that user
and nobody else. With any other owner and mode `0600`, the container cannot read its
config and keeps restarting. After this, edit the file with `sudo`:

```sh
chmod 600 contrib/packaging/docker/config.yaml
sudo chown 1001:1001 contrib/packaging/docker/config.yaml
```

`cookie_secure` is `true` in the sample, which is right behind a TLS-terminating proxy.
For plain HTTP on anything but `localhost`, set it to `false`, or browsers drop the
session cookie.

Then start it:

```sh
cd contrib/packaging/docker
docker compose up -d
docker compose exec signet signet user-add user@example.com
```

Or without Compose, from the repository root:

```sh
docker run -d \
  --name signet \
  -p 8080:8080 \
  -v $(pwd)/contrib/packaging/docker/config.yaml:/etc/signet/config.yaml:ro \
  -v signet-data:/var/lib/signet \
  signet:latest
```

## Mail

Email PINs need a mail relay, and the container has no mail server of its own. Signet runs
`mail.program`, which is `/usr/sbin/sendmail`. In this image that is BusyBox's, a small client
that connects to `127.0.0.1:25` unless the `SMTPHOST` environment variable names a relay:

```yaml
    environment:
      - SMTPHOST=mail.example.com
```

The relay must accept mail from the container's address without a login, and `mail.from_address`
must be an address that can receive mail, because bounces go there.

Without a relay no PIN is sent. So that a refused address cannot reveal whether an account
exists, the user still sees the normal reply, and the error appears only in `docker logs`.

## Volumes and paths

- `/var/lib/signet`: the SQLite3 database and CSV file. Keep this on a volume.
- `/etc/signet/config.yaml`: your configuration.
- `/etc/signet/templates`, `/etc/signet/static`: the default pages, in the image. Mount a
  directory over either one to replace it. `serve` refuses to start if a template cannot
  be read or parsed, or there is no login page, so files you mount must be readable by
  uid 1001.

## Environment variables

- `TZ`: timezone (default: UTC)
- `SMTPHOST`: the mail relay; see "Mail"

## Health and logs

```sh
docker inspect --format='{{.State.Health.Status}}' signet
docker logs -f signet
```

With Compose, use `docker compose ps` and `docker compose logs -f`.

## Stopping it

```sh
docker compose down          # or: docker stop signet && docker rm signet
```

The volume keeps the accounts and sessions.

## Documentation

- [Signet README](../../../README.md)
- [Signet design](../../../docs/DESIGN.md)
