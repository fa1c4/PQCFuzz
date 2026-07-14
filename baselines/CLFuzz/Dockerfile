ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    git \
    patch \
    make \
    cmake \
    ninja-build \
    python3 \
    python3-pip \
    python3-yaml \
    ca-certificates \
    pkg-config \
    libboost-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/PQC-DF
