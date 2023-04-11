# Binary distribution internals

## Reproducibility

The binaries we build in GitHub Actions and distribute in [our releases](https://github.com/status-im/nimbus-eth2/releases) come
from an intricate process meant to ensure [reproducibility](https://reproducible-builds.org/).

While the ability to produce the same exact binaries from the corresponding Git
commits is a good idea for any open source project, it is a requirement
for software that deals with digital tokens of significant value.

## Docker containers for internal use

The easiest way to guarantee that users are able to replicate
our binaries for themselves is to give them the same software environment we used in CI. Docker
containers fit the bill, so everything starts with the architecture- and
OS-specific containers in `docker/dist/base_image/`.

These images contain all the packages we need, are built and published once (to
Docker Hub), and are then reused as the basis for temporary Docker
images where the `nimbus-eth2` build is carried out.

These temporary images are controlled by Dockerfiles in `docker/dist/`. Since
we're not publishing them anywhere, we can customize them to the system
they run on (we ensure they use the host's UID/GID, the host's QEMU static
binaries, etc); they get access to the source code through the use of external volumes.

## Build process

It all starts from the GitHub actions in `.github/workflows/release.yml`.
There is a different job for each supported OS-architecture combination and they all
run in parallel (ideally).

Once all those CI jobs are completed successfully, a GitHub release draft is created
and all the distributable archives are uploaded to it.
A list of checksums for
the main binaries is inserted in the release description.
That draft needs to be manually published.

The build itself is triggered by a Make target, e.g. `make dist-amd64`.
This invokes `scripts/make_dist.sh` which builds the corresponding Docker container from
`docker/dist/` and runs it with the Git repository's top directory as an external
volume.

The entry point for that container is `docker/dist/entry_point.sh` and that's
where you'll find the Make invocations needed to finally build the software and
create distributable tarballs.

## Docker images for end users

Configured in `.github/workflows/release.yml` (only for Linux AMD64, ARM and
ARM64), we unpack the distribution tarball and copy its content into a third
type of Docker image — meant for end users and defined by
`docker/dist/binaries/Dockerfile.amd64` (and related).

We then publish that to [Docker Hub](https://hub.docker.com/r/statusim/nimbus-eth2).
