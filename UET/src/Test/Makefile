# Smart Makefile for Soft-UE Test
# Automatically detects cpp files in current directory and supports user-selected compilation targets

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g -pthread -w
INCLUDES = -I.. -I../SES -I../PDS -I../PDS/PDC -I../PDS/PDS_Manager -I../logger

# Windows platform needs ws2_32 library
ifeq ($(OS),Windows_NT)
	LDFLAGS = -lws2_32
else
	LDFLAGS =
endif

# Auto-discover test files in current directory
TEST_FILES = $(wildcard *.cpp)
PDC_SOURCES = ../PDS/PDC/PDC.cpp \
              ../PDS/PDC/IPDC.cpp \
              ../PDS/PDC/TPDC.cpp \
              ../PDS/PDC/RTOTimer/RTOTimer.cpp \
              ../Network_Layer/UDP_Network_Layer.cpp

# Default compilation target (modifiable)
DEFAULT_TARGET = PDS_fulltest

# Get filenames without extension
TARGETS = $(basename $(TEST_FILES))

# Current selected compilation target
TARGET ?= $(DEFAULT_TARGET)

# Get corresponding source file
CURRENT_SOURCE = $(TARGET).cpp
SOURCES = $(CURRENT_SOURCE) $(PDC_SOURCES)

# Dependency header file paths
DEPS = ../SES/SES.hpp \
       ../Transport_Layer.hpp \
       ../PDS/PDS_Manager/PDSManager.hpp \
       ../PDS/PDC/PDC.hpp \
       ../PDS/PDC/IPDC.hpp \
       ../PDS/PDC/TPDC.hpp \
       ../PDS/PDC/RTOTimer/RTOTimer.hpp \
       ../PDS/PDC/process/IPDCProcessManager.hpp \
       ../PDS/PDC/process/TPDCProcessManager.hpp \
       ../PDS/PDC/process/ThreadSafeQueue.hpp \
       ../logger/Logger.hpp \
       ../logger/LoggingEnhancer.hpp \
       ../Network_Layer/UDP_Network_Layer.hpp \
       ../PDS/PDS_Manager/process/PDSProcessManager.hpp

# ==================== Main Targets ====================

# Default target
all: $(TARGET)

# Compile specified target
$(TARGET): $(CURRENT_SOURCE) $(PDC_SOURCES) $(DEPS)
	@echo "Compiling: $(TARGET)"
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $(TARGET) $(SOURCES) $(LDFLAGS)
	@echo "Compilation complete: $(TARGET)"

# Run current target
run: $(TARGET)
	@echo "Running: $(TARGET)"
	./$(TARGET)

# Compile and run
test: $(TARGET)
	@echo "Compiling and running: $(TARGET)"
	./$(TARGET)

# ==================== Multi-Target Support ====================

# Create compilation targets for each discovered cpp file
define TARGET_template
$(1): $(1).cpp $(PDC_SOURCES) $(DEPS)
	@echo "Compiling: $(1)"
	$$(CXX) $$(CXXFLAGS) $$(INCLUDES) -o $(1) $(1).cpp $$(PDC_SOURCES) $$(LDFLAGS)
	@echo "Compilation complete: $(1)"

run_$(1): $(1)
	@echo "Running: $(1)"
	./$(1)

test_$(1): $(1)
	@echo "Compiling and running: $(1)"
	./$(1)
endef

# Generate targets for each test file
$(foreach target,$(TARGETS),$(eval $(call TARGET_template,$(target))))

# ==================== Maintenance Targets ====================

# Clean all compilation artifacts
clean:
	@echo "Cleaning compilation artifacts..."
	rm -f $(TARGETS) *.log *.o
	@echo "Clean complete"

# Clean and rebuild default target
rebuild: clean all

# Debug compile current target
debug: CXXFLAGS += -DDEBUG -g3
debug: $(TARGET)

# List all available test files
list:
	@echo "Discovered test files:"
# @for file in $(TEST_FILES); do echo "  - $$file"; done
	@echo ""
	@echo "Available compilation targets:"
	@for target in $(TARGETS); do echo "  - $$target"; done
	@echo ""
	@echo "Current default target: $(DEFAULT_TARGET)"
	@echo ""
	@echo "Usage:"
	@echo "  make                    # Compile default target"
	@echo "  make TARGET=xxx         # Compile specified target"
	@echo "  make xxx                # Compile specified target"
	@echo "  make run               # Run current target"
	@echo "  make run_xxx           # Compile and run specified target"
	@echo "  make list              # Show all available targets"
	@echo "  make clean             # Clean compilation artifacts"
	@echo "  make debug             # Debug compilation"

# Show detailed help
help:
	@echo "Smart Soft-UE Test Compiler"
	@echo "============================"
	@echo ""
	@make list
	@echo ""
	@echo "Examples:"
	@echo "  make                           # Compile PDS_fulltest"
	@echo "  make TARGET=SESTest            # Compile SESTest"
	@echo "  make SESTest                   # Compile SESTest"
	@echo "  make run_SESTest               # Compile and run SESTest"
	@echo "  make debug TARGET=PDS_test     # Debug compile PDS_test"

# Check if source files exist
check:
	@echo "Checking source files..."
	@for file in $(TEST_FILES); do \
		if [ -f $$file ]; then \
			echo "✓ $$file"; \
		else \
			echo "✗ $$file (missing)"; \
		fi; \
	done
	@echo ""
	@echo "PDC dependency files:"
	@for file in $(PDC_SOURCES); do \
		if [ -f $$file ]; then \
			echo "✓ $$file"; \
		else \
			echo "✗ $$file (missing)"; \
		fi; \
	done

# Set default goal
.DEFAULT_GOAL := all

# Declare phony targets
.PHONY: all run test clean rebuild debug list help check $(foreach target,$(TARGETS),run_$(target) test_$(target))