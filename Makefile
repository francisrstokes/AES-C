CC=gcc
MKDIR=mkdir -p
RM=rm -rf

INC_DIR=inc
SRC_DIR=src
OBJ_DIR=obj
BUILD_DIR=build

IFLAGS=-I inc
CFLAGS=-g

INC_FILES=$(wildcard inc/*.h)
SRC_FILES=$(wildcard src/*.c)
OBJ_FILES:=$(patsubst $(SRC_DIR)/%, $(OBJ_DIR)/%, $(patsubst %.c, %.o, $(SRC_FILES)))

OTHER_DEPS=$(INC_DIR)/*.h Makefile

EXE=main

.PHONY: all clean test

all: $(BUILD_DIR)/$(EXE)

$(BUILD_DIR)/$(EXE): $(OBJ_FILES)
	$(MKDIR) $(BUILD_DIR)
	$(CC) $^ -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(OTHER_DEPS)
	$(MKDIR) $(OBJ_DIR)
	$(CC) $(IFLAGS) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJ_DIR)/* $(BUILD_DIR)/*

test: $(BUILD_DIR)/$(EXE)
	$(BUILD_DIR)/$(EXE) -t