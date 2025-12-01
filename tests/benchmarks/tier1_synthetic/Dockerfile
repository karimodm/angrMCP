FROM ubuntu:22.04

RUN apt-get update && apt-get install -y build-essential gcc

WORKDIR /app

COPY vuln_server.c .

# Compile with protections disabled to make it a classic/easy target
# -fno-stack-protector: Disable stack canaries
# -z execstack: Allow executable stack
# -no-pie: Disable Position Independent Executable
RUN gcc -o vuln_server vuln_server.c -fno-stack-protector -z execstack -no-pie

CMD ["./vuln_server"]
