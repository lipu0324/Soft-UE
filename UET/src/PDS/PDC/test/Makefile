# Makefile for PDC Tests
# 编译PDC测试程序

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g
INCLUDES = -I.. -I../.. -I../../.. -I../../../logger

# 目标程序
TARGETS = ipdc_rto_test

# 通用依赖
RTO_SOURCES = ../RTOTimer/RTOTimer.cpp
PDC_SOURCES = ../PDC.cpp
IPDC_SOURCES = ../IPDC.cpp

# 依赖的头文件路径
DEPS = ../process/TPDCProcessManager.hpp \
       ../process/IPDCProcessManager.hpp \
       ../process/ThreadSafeQueue.hpp \
       ../TPDC.hpp \
       ../IPDC.hpp \
       ../PDC.hpp \
       ../../PDS.hpp


# 编译所有目标
all: $(TARGETS)

# PDC关闭状态测试
pdc_close_status_test: pdc_close_status_test.cpp $(RTO_SOURCES) $(DEPS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o pdc_close_status_test pdc_close_status_test.cpp $(RTO_SOURCES) -lpthread

# PDC超时重传测试
pdc_rto_test: pdc_rto_test.cpp $(RTO_SOURCES) $(DEPS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o pdc_rto_test pdc_rto_test.cpp $(RTO_SOURCES) -lpthread

# IPDC超时重传测试
ipdc_rto_test: ipdc_rto_test.cpp $(PDC_SOURCES) $(IPDC_SOURCES) $(RTO_SOURCES) $(DEPS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o ipdc_rto_test ipdc_rto_test.cpp $(PDC_SOURCES) $(IPDC_SOURCES) $(RTO_SOURCES) -lpthread

# 运行所有测试
test: $(TARGETS)
	@echo "=========================================="
	@echo "运行所有PDC测试"

	@echo ""
	@echo "3. IPDC超时重传测试"
	@echo "------------------------------------------"
	./ipdc_rto_test

# 运行单个测试

test-ipdc: ipdc_rto_test
	./ipdc_rto_test

# 清理
clean:
	rm -f $(TARGETS)

# 调试编译
debug: CXXFLAGS += -DDEBUG -g3
debug: $(TARGETS)

# 显示帮助
help:
	@echo "可用目标:"
	@echo "  all                    - 编译所有测试程序"
	@echo "  pdc_close_status_test  - 编译PDC关闭状态测试"
	@echo "  pdc_rto_test          - 编译PDC超时重传测试"
	@echo "  ipdc_rto_test         - 编译IPDC超时重传测试"
	@echo "  test                  - 编译并运行所有测试"
	@echo "  test-close            - 运行PDC关闭状态测试"
	@echo "  test-rto              - 运行PDC超时重传测试"
	@echo "  test-ipdc             - 运行IPDC超时重传测试"
	@echo "  debug                 - 编译调试版本"
	@echo "  clean                 - 清理编译文件"
	@echo "  help                  - 显示此帮助信息"

.PHONY: all test test-close test-rto test-ipdc clean debug help