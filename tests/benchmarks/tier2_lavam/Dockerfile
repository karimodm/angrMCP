## Minimal, self-contained vulnerable build of the real `file` 5.22
# We bypass the full LAVA pipeline (Postgres, PANDA, qcow downloads) and instead
# inject a deterministic buffer overflow into the preprocessed `file` source.

FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential clang make zlib1g-dev curl ca-certificates && \
    update-ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

# Fetch vanilla file-5.22 source (no preprocessed headers), with a mirror fallback
RUN curl -L https://astron.com/pub/file/file-5.22.tar.gz -o file.tar.gz || \
    curl -L https://ftp.osuosl.org/pub/blfs/conglomeration/file/file-5.22.tar.gz -o file.tar.gz
RUN tar xf file.tar.gz -C /tmp

WORKDIR /tmp/file-5.22

# Inject a subtle stack overflow in a constructor; trigger via LAVA_PAYLOAD
RUN cat >> src/file.c <<'EOF'
#include <stdlib.h>
#include <string.h>
__attribute__((constructor))
static void init_misc(void) {
    const char *p = getenv("LAVA_PAYLOAD");
    if (!p) return;
    char buf[64];
    size_t n = strlen(p) + 1;
    memcpy(buf, p, n); // overflow when n > 64
}
EOF

# Configure & build (no stack protector, no PIE) then strip symbols
RUN CFLAGS='-O0 -g -fno-stack-protector -fno-pie' LDFLAGS='-no-pie' ./configure --prefix=/usr --disable-shared && \
    make -j"$(nproc)" && \
    strip src/file

# Collect artifacts
RUN cp src/file /tmp/vuln_file && \
    cp magic/magic.mgc /tmp/magic.mgc

FROM ubuntu:22.04
WORKDIR /app
COPY --from=builder /tmp/vuln_file /app/vuln_file
COPY --from=builder /tmp/magic.mgc /app/magic.mgc

ENV MAGIC=/app/magic.mgc

CMD ["/app/vuln_file", "--help"]
