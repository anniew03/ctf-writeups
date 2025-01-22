FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update && \
    apt-get install -y socat coreutils python3 python3-pip python3-dev \
        libssl-dev build-essential gdb gdbserver tmux vim git strace tmux \
        xterm libc6-i386

RUN pip3 install --upgrade pwntools --break-system-packages

RUN mkdir /ctf

COPY ./chall /ctf/chall
WORKDIR /ctf/chall
RUN chmod +x ./vuln

WORKDIR /ctf

ENV export LC_CTYPE=C.UTF-8

CMD socat -T 30 \
    TCP-LISTEN:1337,nodelay,reuseaddr,fork \
    EXEC:"stdbuf -i0 -o0 /ctf/chall/vuln"
