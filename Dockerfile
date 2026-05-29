FROM scratch
COPY target/x86_64-unknown-linux-musl/release/ghost-nas /ghost-nas
ENTRYPOINT ["/ghost-nas"]
