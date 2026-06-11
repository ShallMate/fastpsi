# Ultra-Fast Private Set Intersection from Efficient Oblivious Key-Value Stores



**This is a PSI implementation with extremely low communication overhead while maintaining high efficiency, including a new low-redundancy and efficient OKVS and PSI protocol.**


## Build
```
git clone https://github.com/ShallMate/yacl.git
cd yacl/examples/
git clone https://github.com/ShallMate/fastpsi.git
cd ..
bazel --batch build --config=one //examples/fastpsi:fastpsi
cd bazel-bin/examples/fastpsi
./fastpsi
```
