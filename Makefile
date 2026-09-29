# Build the imported Soft-UE core independently of the legacy provider.
CXX = g++
CXXFLAGS ?= -std=c++17 -O2 -g -pthread
CORE := UET/src
BUILD := build
PDS_SOURCES := $(CORE)/Test/PDS_fulltest.cpp \
  $(CORE)/PDS/PDC/PDC.cpp \
  $(CORE)/PDS/PDC/IPDC.cpp \
  $(CORE)/PDS/PDC/TPDC.cpp \
  $(CORE)/PDS/PDC/RTOTimer/RTOTimer.cpp \
  $(CORE)/Network_Layer/UDP_Network_Layer.cpp
CORE_HEADERS := $(shell find $(CORE) -name '*.hpp' -o -name '*.h')

.PHONY: core test-core test-ses-payload test-pds-loopback test-pds-process-loopback test-pds-rdma-queue test-pds-process-rdma-e2e check-env message-lib rdma-message test-rdma test-udp test-codec
core: $(BUILD)/PDS_fulltest

$(BUILD):
	mkdir -p $@

$(BUILD)/PDS_fulltest: $(PDS_SOURCES) $(CORE_HEADERS) | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(CORE) $(PDS_SOURCES) -o $@ $(LDFLAGS) $(LDLIBS)

test-core: core
	@cd $(BUILD) && { timeout 45 ./PDS_fulltest > PDS_fulltest.log 2>&1 || { tail -n 50 PDS_fulltest.log; exit 1; }; }
	@echo "PDS_fulltest exited successfully; log: build/PDS_fulltest.log"

$(BUILD)/ses_payload_test: $(CORE)/Test/SesPayloadIntegrationTest.cpp $(PDS_SOURCES) $(CORE_HEADERS) $(BUILD)/libsoftue_message.a | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(CORE) $(CORE)/Test/SesPayloadIntegrationTest.cpp \
	  $(CORE)/PDS/PDC/PDC.cpp $(CORE)/PDS/PDC/IPDC.cpp $(CORE)/PDS/PDC/TPDC.cpp \
	  $(CORE)/PDS/PDC/RTOTimer/RTOTimer.cpp $(CORE)/Network_Layer/UDP_Network_Layer.cpp \
	  $(BUILD)/libsoftue_message.a -o $@ $(LDFLAGS) $(LDLIBS)

test-ses-payload: $(BUILD)/ses_payload_test
	./$(BUILD)/ses_payload_test

$(BUILD)/pds_runtime_loopback_test: $(CORE)/Test/PdsRuntimeLoopbackTest.cpp $(PDS_SOURCES) $(CORE_HEADERS) $(BUILD)/libsoftue_message.a | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(CORE) $(CORE)/Test/PdsRuntimeLoopbackTest.cpp \
	  $(filter-out $(CORE)/Test/PDS_fulltest.cpp,$(PDS_SOURCES)) $(BUILD)/libsoftue_message.a -o $@ $(LDFLAGS) $(LDLIBS)

test-pds-loopback: $(BUILD)/pds_runtime_loopback_test
	./$(BUILD)/pds_runtime_loopback_test

$(BUILD)/pds_process_loopback_test: $(CORE)/Test/PdsProcessLoopbackTest.cpp $(PDS_SOURCES) $(CORE_HEADERS) $(BUILD)/libsoftue_message.a | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(CORE) $< \
	  $(filter-out $(CORE)/Test/PDS_fulltest.cpp,$(PDS_SOURCES)) $(BUILD)/libsoftue_message.a -o $@ $(LDFLAGS) $(LDLIBS)

test-pds-process-loopback: $(BUILD)/pds_process_loopback_test
	./$(BUILD)/pds_process_loopback_test

$(BUILD)/pds_rdma_queue_loopback_test: $(CORE)/Test/PdsRdmaQueueLoopbackTest.cpp $(CORE_HEADERS) $(BUILD)/libsoftue_message.a | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(CORE) $< $(BUILD)/libsoftue_message.a -o $@ $(LDFLAGS) -libverbs $(LDLIBS)

test-pds-rdma-queue: $(BUILD)/pds_rdma_queue_loopback_test
	python3 scripts/test_pds_rdma_queue_loopback.py

$(BUILD)/pds_process_rdma_e2e_test: $(CORE)/Test/PdsProcessRdmaE2ETest.cpp $(CORE_HEADERS) $(BUILD)/libsoftue_message.a | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(CORE) $< \
	  $(filter-out $(CORE)/Test/PDS_fulltest.cpp,$(PDS_SOURCES)) $(BUILD)/libsoftue_message.a -o $@ $(LDFLAGS) -libverbs $(LDLIBS)

test-pds-process-rdma-e2e: $(BUILD)/pds_process_rdma_e2e_test
	python3 scripts/test_pds_process_rdma_e2e.py

MESSAGE_SOURCES := $(CORE)/Network_Layer/PacketCodec.cpp \
  $(CORE)/Network_Layer/PdsPacketCodec.cpp \
  $(CORE)/Network_Layer/PdsQueueTransport.cpp \
  $(CORE)/Network_Layer/RdmaChannel.cpp \
  $(CORE)/Network_Layer/UdpChannel.cpp \
  $(CORE)/PDS/MessageStream.cpp \
  $(CORE)/SES/MessageEndpoint.cpp
MESSAGE_OBJECTS := $(patsubst %.cpp,$(BUILD)/%.o,$(MESSAGE_SOURCES))

message-lib: $(BUILD)/libsoftue_message.a

$(BUILD)/%.o: %.cpp $(CORE_HEADERS)
	mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(CORE) -c $< -o $@

$(BUILD)/libsoftue_message.a: $(MESSAGE_OBJECTS)
	ar rcs $@ $^

rdma-message: $(BUILD)/rdma_message_test

$(BUILD)/rdma_message_test: $(CORE)/Test/RdmaMessageTest.cpp $(BUILD)/libsoftue_message.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(CORE) $< $(BUILD)/libsoftue_message.a -o $@ $(LDFLAGS) -libverbs $(LDLIBS)

test-rdma: rdma-message
	python3 scripts/test_rdma_message.py

test-udp: rdma-message
	python3 scripts/test_rdma_message.py --udp

$(BUILD)/packet_codec_test: $(CORE)/Test/PacketCodecTest.cpp $(BUILD)/libsoftue_message.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(CORE) $< $(BUILD)/libsoftue_message.a -o $@ $(LDFLAGS) $(LDLIBS)

test-codec: $(BUILD)/packet_codec_test
	./$(BUILD)/packet_codec_test

check-env:
	bash scripts/check_rdma_env.sh
