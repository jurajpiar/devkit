# Embedded proxy binaries

`make build` compiles the Linux egress proxy into this directory, then embeds
it in the devkit binary. The default output on Apple silicon is
`egressproxy-linux-arm64`; use `GUEST_ARCH=amd64` to build for an x86-64 guest.

These generated binaries are ignored by Git.
