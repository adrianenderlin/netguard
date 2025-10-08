GO      ?= go
ARCH    ?= x86
CLANG   ?= clang
CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)

# Wenn du lokale Kernel-Header nutzt (optional):
# CFLAGS  += -I$(HOME)/linux/include

BIN := net-guard

BPF_DIR   := bpf
BPF_SRCS  := $(BPF_DIR)/tc_rl.bpf.c $(BPF_DIR)/xdp_allow_deny.bpf.c
BPF_OBJS  := $(BPF_SRCS:.c=.o)

all: $(BPF_OBJS) $(BIN)

$(BPF_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BIN): go.mod $(wildcard *.go) $(BPF_OBJS)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN) .

clean:
	rm -f $(BPF_DIR)/*.o $(BIN)

.PHONY: all clean

