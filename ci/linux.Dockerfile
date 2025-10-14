FROM harbor.status.im/infra/ci-build-containers:linux-base-1.0.0
USER root

RUN apt-get update && apt-get install -yq --no-install-recommends \
    figlet \
    git \
    git-lfs \
    make \
    openssl \
    lsof \
    psmisc \
    procps \
    curl \
    jq \
    openjdk-17-jre-headless \
    python3 \
    python3-pip \
    python3-venv \
    gcc-11 \
    g++-11 \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 100 \
    && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 100

RUN ln -sf /usr/bin/gcc /usr/bin/cc \
    && ln -sf /usr/bin/g++ /usr/bin/c++

RUN pip3 install --no-cache-dir --break-system-packages \
    mkdocs \
    mkdocs-material \
    mkdocs-material-extensions \
    pymdown-extensions

USER jenkins
ENTRYPOINT [""]