# The build is reproducible only if this base image stays the same.
FROM  statusteam/nimbus_beacon_node:dist_base_20201008172919@sha256:7190a4d54e56aa4a45fa3032381a43dcec89f23e6d7ed5dfb0f98967f92bf522

SHELL ["/bin/bash", "-c"]

ARG USER_ID
ARG GROUP_ID

RUN addgroup --gid ${GROUP_ID} user; \
	adduser --disabled-password --gecos '' --uid ${USER_ID} --gid ${GROUP_ID} user;

USER user

STOPSIGNAL SIGINT

COPY "entry_point.sh" "/home/user/"
ENTRYPOINT ["/home/user/entry_point.sh"]

