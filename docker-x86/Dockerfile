FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3 python3-pip gdb gdbserver \
    git curl netcat-openbsd file binutils
RUN pip3 install pwntools
WORKDIR /chall
