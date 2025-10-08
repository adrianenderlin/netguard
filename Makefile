# ==== Config ====
GO      ?= go
ARCH    ?= x86          # arm64, s390x, etc. je nach Ziel
CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)

BIN := net-guard

# ==== Targets ====
all: xdp_allow_deny.bpf.o tc_rl.bpf.o $(BIN)

xdp_allow_deny.bpf.o: xdp_allow_deny.bpf.c
	clang $(CFLAGS) -c $< -o $@

tc_rl.bpf.o: tc_rl.bpf.c
	clang $(CFLAGS) -c $< -o $@

$(BIN): go.mod main.go
	$(GO) build -trimpath -ldflags="-s -w" -o $(BIN) .

clean:
	rm -f *.o $(BIN)

.PHONY: all clean

