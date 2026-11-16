FROM archlinux:base

# Initialize pacman keyring and update base system
RUN pacman-key --init && \
    pacman-key --populate archlinux && \
    pacman -Syu --noconfirm && \
    pacman -S --noconfirm --needed \
        bash \
        coreutils \
        util-linux \
        sudo \
        curl \
        wget \
        git \
        nano \
        vim \
        procps-ng \
        iproute2 \
        iputils \
        tar \
        gzip \
        which \
        ca-certificates && \
    pacman -Scc --noconfirm

# Set up clean environment and locale
RUN echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    locale-gen || true

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8 \
    TERM=xterm-256color \
    HOME=/root

WORKDIR /root

CMD ["/bin/bash"]
