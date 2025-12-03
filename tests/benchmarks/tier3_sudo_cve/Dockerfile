FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    wget \
    build-essential \
    libpam0g-dev \
    libldap2-dev \
    libssl-dev \
    python3 \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Download vulnerable sudo
RUN wget https://www.sudo.ws/dist/sudo-1.8.31.tar.gz && \
    tar -xf sudo-1.8.31.tar.gz && \
    rm sudo-1.8.31.tar.gz

WORKDIR /app/sudo-1.8.31

# Configure and build
RUN ./configure --prefix=/usr --with-pam && \
    make && \
    make install

# Create a non-root user
RUN useradd -m -s /bin/bash lowpriv && \
    echo "lowpriv:password" | chpasswd

# Switch to lowpriv user
USER lowpriv
WORKDIR /home/lowpriv

CMD ["/bin/bash"]
