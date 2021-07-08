## directory layout

### dist/base_image/

Base Docker images for building distributable binaries. Uploaded to
Docker Hub (we need them to reproduce officially released builds).

### dist/

Dockerfiles used to build local Docker images based on the base images
described above. Only used for generating distributable binaries. Not uploaded
to Docker Hub.

### dist/binaries/

Docker images for end-users, obtained by copying distributable binaries inside
official Debian images. Uploaded to Docker Hub as part of the CI release process.

Also contains some example `docker-compose` configuration files.

## more details

See the ["Binary distribution internals"](https://nimbus.guide/distribution_internals.html) page of the Nimbus book.
