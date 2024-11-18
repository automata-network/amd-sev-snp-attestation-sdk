cbindings:
	mkdir -p c
	cargo build --features clib --release
	cp target/release/libsev.so c/libsev.so
	cp target/release/libsev_snp.so c/libsev_snp.so

.PHONY: cbindings