# Build environment for the BOUND node (Ubuntu 24.04, GCC 13, the README's packages; apt checks
# every package's signature). No Qt: boundd and bound-cli only.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build pkg-config git ca-certificates python3 \
      libsodium-dev libleveldb-dev libsnappy-dev nlohmann-json3-dev libgtest-dev \
    && rm -rf /var/lib/apt/lists/*
