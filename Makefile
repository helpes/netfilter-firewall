# プロジェクト設定
CC 	    := gcc
CFLAGS  := -g -Wall -Icommon/include -Ifirewall/include -Icli/include
LDFLAGS := -lnetfilter_queue

# ディレクトリ
BUILD_DIR        := build
COMMON_OBJ_DIR   := $(BUILD_DIR)/common
FIREWALL_OBJ_DIR := $(BUILD_DIR)/firewall
CLI_OBJ_DIR      := $(BUILD_DIR)/cli
COMMON_SRC_DIR   := common/src
FIREWALL_SRC_DIR := firewall/src
CLI_SRC_DIR      := cli/src

# ソースファイル
COMMON_SRCS   := $(shell find $(COMMON_SRC_DIR) -name "*.c")
FIREWALL_SRCS := $(shell find $(FIREWALL_SRC_DIR) -name "*.c")
CLI_SRCS      := $(shell find $(CLI_SRC_DIR) -name "*.c")

# オブジェクトファイル
COMMON_OBJS   := $(patsubst $(COMMON_SRC_DIR)/%.c, $(COMMON_OBJ_DIR)/%.o, $(COMMON_SRCS))
FIREWALL_OBJS := $(patsubst $(FIREWALL_SRC_DIR)/%.c, $(FIREWALL_OBJ_DIR)/%.o, $(FIREWALL_SRCS))
CLI_OBJS      := $(patsubst $(CLI_SRC_DIR)/%.c, $(CLI_OBJ_DIR)/%.o, $(CLI_SRCS))

# 実行ファイル
FIREWALL_EXEC := $(BUILD_DIR)/fw
CLI_EXEC      := $(BUILD_DIR)/fw_ctl

# デフォルトターゲット
.PHONY: all clean
all: $(FIREWALL_EXEC) $(CLI_EXEC)

# 実行ファイルの生成
$(FIREWALL_EXEC): $(FIREWALL_OBJS) $(COMMON_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(CLI_EXEC): $(CLI_OBJS) $(COMMON_OBJS)
	$(CC) $(CFLAGS) $^ -o $@

# オブジェクトファイルの生成
$(COMMON_OBJ_DIR)/%.o: $(COMMON_SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(CLI_OBJ_DIR)/%.o: $(CLI_SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(FIREWALL_OBJ_DIR)/%.o: $(FIREWALL_SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)