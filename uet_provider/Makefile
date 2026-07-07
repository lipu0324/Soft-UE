# Build UET libfabric provider plugin (phase 1: FI_MSG + CQ + AV over UDP shim)
#
# Output: libuet-fi.so
# Usage:
#   make -C uet_provider
#   FI_PROVIDER_PATH=$(pwd)/uet_provider fi_info -p uet
#   FI_PROVIDER_PATH=$(pwd)/uet_provider fi_pingpong -p uet -e dgram -v ...

CXX ?= g++
PKG_CONFIG ?= pkg-config

TARGET := libuet-fi.so

UET_ROOT := ../UET/src
UET_SRC_ROOT := $(UET_ROOT)
UET_CORE_SOURCES_MK := $(UET_ROOT)/UETCoreSources.mk
include $(UET_CORE_SOURCES_MK)

INCLUDES := \
	-I.. \
	-I$(UET_ROOT) \
	-I$(UET_ROOT)/SES \
	-I$(UET_ROOT)/PDS \
	-I$(UET_ROOT)/PDS/PDC \
	-I$(UET_ROOT)/PDS/PDS_Manager \
	-I$(UET_ROOT)/logger \
	$(shell $(PKG_CONFIG) --cflags libfabric) \
	$(shell $(PKG_CONFIG) --cflags libibverbs 2>/dev/null || $(PKG_CONFIG) --cflags ibverbs 2>/dev/null) \
	$(shell $(PKG_CONFIG) --cflags librdmacm 2>/dev/null || true)

CXXFLAGS ?= -std=gnu++17 -O2 -g -fPIC -Wall -Wextra -pthread
LDFLAGS := -shared $(shell $(PKG_CONFIG) --libs libfabric) $(shell $(PKG_CONFIG) --libs libibverbs 2>/dev/null || $(PKG_CONFIG) --libs ibverbs 2>/dev/null || echo -libverbs) $(shell $(PKG_CONFIG) --libs librdmacm 2>/dev/null || echo -lrdmacm)

UET_PROVIDER_SOURCES := $(UET_CORE_RUNTIME_SOURCES)

SOURCES := \
	uet_provider.cpp \
	$(UET_PROVIDER_SOURCES)

# Catch refactors that move implementations out of headers into .cpp files.
HEADER_DEPS := $(shell find $(UET_ROOT)/SES $(UET_ROOT)/PDS $(UET_ROOT)/Network_Layer $(UET_ROOT)/logger -type f \( -name '*.hpp' -o -name '*.h' \))

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADER_DEPS) $(UET_CORE_SOURCES_MK)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET)

fi_info: $(TARGET)
	FI_PROVIDER_PATH=$$(pwd) fi_info -p uet

.PHONY: all clean fi_info
