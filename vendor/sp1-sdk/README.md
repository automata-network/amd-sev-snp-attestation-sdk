## Groth16 CUDA acceleration using Icicle

To use GPU/CUDA acceleration using [Icicle](https://github.com/ingonyama-zk/icicle-gnark), you need to enable the `groth16-cuda` feature, as well as perform the following setup ahead of time

Installing Icicle shared libraries:
```sh
git clone https://github.com/ingonyama-zk/icicle-gnark
cd icicle-gnark/wrappers/golang
sudo ./build.sh -curve=all
```

These runtime environment variables are required:
```sh
export ICICLE_BACKEND_INSTALL_DIR="/usr/local/lib/backend/"
export LD_LIBRARY_PATH="/usr/local/lib"
```
