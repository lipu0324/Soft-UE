# UDP网络层转发器编译配置
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -I../
LDFLAGS = 
LIBS = 

# Windows平台需要额外的库
ifeq ($(OS),Windows_NT)
	LIBS += -lws2_32
endif

# 目标文件
OBJS = UDP_Network_Layer.o test_udp_forwarder.o

# 默认目标
all: test_udp_forwarder

# 测试程序
test_udp_forwarder: $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

# 编译源文件
UDP_Network_Layer.o: UDP_Network_Layer.cpp UDP_Network_Layer.hpp
	$(CXX) $(CXXFLAGS) -c $<

test_udp_forwarder.o: test_udp_forwarder.cpp UDP_Network_Layer.hpp
	$(CXX) $(CXXFLAGS) -c $<

# 清理
clean:
	rm -f $(OBJS) test_udp_forwarder

.PHONY: all clean