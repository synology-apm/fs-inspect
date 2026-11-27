# The runner image of `cargo xtask act`: what .github/workflows/ci.yml expects of ubuntu-latest,
# and no more. Ubuntu 24.04 for glibc 2.39 (the prebuilt tools taiki-e/install-action fetches
# need it), Node 24 for the JavaScript actions, Python 3.12 (Ubuntu's), and rustup with its
# proxies also on the default PATH; the toolchain itself comes from rust-toolchain.toml.
FROM ubuntu:24.04
ARG TARGETARCH
RUN apt-get update \
 && apt-get install -y --no-install-recommends sudo git ca-certificates curl build-essential xz-utils zstd \
      python3 python3-venv pipx \
 && rm -rf /var/lib/apt/lists/*
RUN case "$TARGETARCH" in arm64) arch=arm64 ;; *) arch=x64 ;; esac \
 && curl -sSfL "https://nodejs.org/dist/v24.11.1/node-v24.11.1-linux-$arch.tar.xz" \
  | tar -xJ -C /usr/local --strip-components=1
ENV RUSTUP_HOME=/root/.rustup CARGO_HOME=/root/.cargo PATH=/root/.cargo/bin:/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none \
 && ln -sf /root/.cargo/bin/* /usr/local/bin/
ENV CARGO_TERM_COLOR=always
