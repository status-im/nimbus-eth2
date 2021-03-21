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
OS-specific containers in `docker/dist/base\_image/`.

These images contain all the packages we need, are built and published once (to
Docker Hub), and are then reused as the basis for temporary Docker
images where the `nimbus-eth2` build is carried out.

These temporary images are controlled by Dockerfiles in `docker/dist/`. Since we're not publishing them anywhere, we can customize them to the system
they run on (we ensure they use the host's UID/GID, the host's QEMU static
binaries, etc); they get access to the source code through the use of external volumes.

## Build process

It all starts from the GitHub actions in `.github/workflows/release.yml`. There
is a different job for each supported OS-architecture combination and they all
run in parallel (ideally).

The `build-amd64` CI job is special, because it creates a new
GitHub release draft, as soon as possible. All the other jobs will upload their
binary distribution tarballs to this draft release, but, since it's not feasible
to communicate between CI jobs, they simply use GitHub APIs to find out what
the latest release is, check that it has the right Git tag, and use that as their
last step.

The build itself is triggered by a Make target: `make dist-amd64`. This invokes
`scripts/make\_dist.sh` which builds the corresponding Docker container from
`docker/dist/` and runs it with the Git repository's top directory as an external
volume.

The entry point for that container is `docker/dist/entry\_point.sh` and that's
where you'll find the Make invocations needed to finally build the software and
create distributable tarballs.

## Docker images for end users

Configured in `.github/workflows/release.yml` (exclusively for the `build-amd64` job):  we unpack the distribution tarball and copy its content into a third type of Docker image - this one meant for end users and defined by `docker/dist/binaries/Dockerfile.amd64`.

We then publish that to [Docker Hub](https://hub.docker.com/r/statusim/nimbus-eth2).

