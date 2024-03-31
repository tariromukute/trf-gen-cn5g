# Notes

Development on docker

```bash
docker run \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_ADMIN \
    -it \
    -v /sys/kernel/debug/:/sys/kernel/debug/ \
    -v `pwd`/:/home ubuntu:latest

# Install all the packets in Dockerfile.traffic.generator.ubuntu

# Install build tools
apt install clang llvm libbpf-dev

cd /home

clang -O2 -emit-llvm -g -c nsh-decap.bpf.c -o - | \
	llc -march=bpf -mcpu=probe -filetype=obj -o nsh-decap.bpf.o

# Attach program
ip link set dev eth0 xdpgeneric obj nsh-decap.bpf.o sec xdp_nsh_decap

# Detach progam
ip link set dev eth0 xdpgeneric off
```

Build image

```bash
docker buildx build --platform=linux/amd64 -t tariromukute/trf-gen-cn5g:latest -f Dockerfile.traffic.generator.ubuntu .
```