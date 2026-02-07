# Ultra-Fast Private Set Intersection from Efficient Oblivious Key-Value Stores



**This is a PSI implementation with extremely low communication overhead while maintaining high efficiency, including a new low-redundancy and efficient OKVS and PSI protocol. We implemented it using the [YACL library](https://github.com/secretflow/yacl).**


## YACL's Prequisites

- **bazel**: [.bazelversion](.bazelversion) file describes the recommended version of bazel. We recommend to use the official [bazelisk](https://github.com/bazelbuild/bazelisk?tab=readme-ov-file#installation) to manage bazel version.
- **gcc >= 10.3**
- **[cmake](https://cmake.org/getting-started/)**
- **[ninja/ninja-build](https://ninja-build.org/)**
- **Perl 5 with core modules** (Required by [OpenSSL](https://github.com/openssl/openssl/blob/master/INSTALL.md#prerequisites))

## Build
```
git clone https://github.com/secretflow/yacl.git
cd yacl/examples/
git clone https://github.com/ShallMate/fastpsi
cd ..
bazel build --linkopt=-ldl //...
cd bazel-bin/examples/fastpsi
./fastpsi
```
