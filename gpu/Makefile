# Build the onionaddress miners.
#
#   make cpu    g++ reference miner        -> ../bin/onionaddress-cpu
#   make cuda   CUDA miner (needs nvcc)    -> ../bin/onionaddress-cuda
#
# CUDA_ARCH defaults to -arch=native; override for cross-compilation, e.g.
#   make cuda CUDA_ARCH=sm_75

CXX ?= g++
NVCC ?= $(shell command -v nvcc 2>/dev/null || ls /usr/local/cuda/bin/nvcc 2>/dev/null || echo nvcc)
CUDA_ARCH ?= native

BIN := ../bin

all: cpu cuda

cpu: $(BIN)/onionaddress-cpu

cuda: $(BIN)/onionaddress-cuda

$(BIN)/onionaddress-cpu: miner_cpu.cpp core.h tables.h | $(BIN)
	$(CXX) -O2 -std=c++17 -Wall -Wextra -o $@ miner_cpu.cpp

$(BIN)/onionaddress-cuda: miner_cuda.cu core.h tables.h | $(BIN)
	$(NVCC) -O3 -std=c++17 -arch=$(CUDA_ARCH) -o $@ miner_cuda.cu

$(BIN):
	mkdir -p $(BIN)

clean:
	rm -f $(BIN)/onionaddress-cpu $(BIN)/onionaddress-cuda

.PHONY: all cpu cuda clean
