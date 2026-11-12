# Build the imported Soft-UE core independently of the legacy provider.
.DEFAULT_GOAL := core
CXX = g++
CXXFLAGS ?= -std=c++17 -O2 -g -pthread
ENABLE_RDMA ?= $(shell pkg-config --exists libibverbs 2>/dev/null && echo 1 || echo 0)
CPPFLAGS += -DSOFTUE_HAS_RDMA=$(ENABLE_RDMA)
RDMA_LIBS = $(if $(filter 1,$(ENABLE_RDMA)),-libverbs,)
CORE := UET/src
BUILD := build
PDS_SOURCES := $(CORE)/Test/PDS_fulltest.cpp \
  $(CORE)/PDS/PDC/PDC.cpp $(CORE)/PDS/PDC/Probe.cpp $(CORE)/PDS/PDC/TransmitTiming.cpp $(CORE)/PDS/PDC/NegativeAcknowledgment.cpp \
  $(CORE)/PDS/PDC/IPDC.cpp \
  $(CORE)/PDS/PDC/TPDC.cpp \
  $(CORE)/PDS/PDC/RTOTimer/RTOTimer.cpp \
  $(CORE)/Network_Layer/UDP_Network_Layer.cpp
CORE_HEADERS := $(shell find $(CORE) -name '*.hpp' -o -name '*.h')
-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)

.PHONY: core test-core test-ses-payload test-pds-loopback test-pds-process-loopback test-pds-rdma-queue test-pds-process-rdma-e2e test-pds-udp-queue check-env message-lib rdma-message test-rdma test-udp test-codec test-interactive-udp clean
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
	  $(CORE)/PDS/PDC/PDC.cpp $(CORE)/PDS/PDC/Probe.cpp $(CORE)/PDS/PDC/TransmitTiming.cpp $(CORE)/PDS/PDC/NegativeAcknowledgment.cpp $(CORE)/PDS/PDC/IPDC.cpp $(CORE)/PDS/PDC/TPDC.cpp \
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

$(BUILD)/pds_udp_queue_loopback_test: $(CORE)/Test/PdsUdpQueueLoopbackTest.cpp $(CORE_HEADERS) $(BUILD)/libsoftue_message.a | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(CORE) $< $(BUILD)/libsoftue_message.a -o $@ $(LDFLAGS) $(LDLIBS)

test-pds-udp-queue: $(BUILD)/pds_udp_queue_loopback_test
	python3 scripts/test_pds_udp_queue_loopback.py

MESSAGE_SOURCES := $(CORE)/Network_Layer/PacketCodec.cpp \
  $(CORE)/Network_Layer/PdsPacketCodec.cpp \
  $(CORE)/Network_Layer/PdsQueueTransport.cpp \
  $(CORE)/Network_Layer/UdpChannel.cpp \
  $(CORE)/PDS/MessageStream.cpp \
  $(CORE)/SES/MessageEndpoint.cpp
MESSAGE_OBJECTS := $(patsubst %.cpp,$(BUILD)/%.o,$(MESSAGE_SOURCES))
ifeq ($(ENABLE_RDMA),1)
MESSAGE_OBJECTS += $(BUILD)/$(CORE)/Network_Layer/RdmaChannel.o
endif

message-lib: $(BUILD)/libsoftue_message.a

$(BUILD)/%.o: %.cpp $(CORE_HEADERS)
	mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -I$(CORE) -c $< -o $@

$(BUILD)/libsoftue_message.a: $(MESSAGE_OBJECTS)
	ar rcs $@ $^

rdma-message: $(BUILD)/rdma_message_test

$(BUILD)/rdma_message_test: $(CORE)/Test/RdmaMessageTest.cpp $(BUILD)/libsoftue_message.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(CORE) $< $(BUILD)/libsoftue_message.a -o $@ $(LDFLAGS) $(RDMA_LIBS) $(LDLIBS)

test-rdma: rdma-message
	python3 scripts/test_rdma_message.py

test-udp: rdma-message
	python3 scripts/test_rdma_message.py --udp

test-interactive-udp: rdma-message
	python3 scripts/test_interactive_udp.py --binary $(BUILD)/rdma_message_test

$(BUILD)/packet_codec_test: $(CORE)/Test/PacketCodecTest.cpp $(BUILD)/libsoftue_message.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(CORE) $< $(BUILD)/libsoftue_message.a -o $@ $(LDFLAGS) $(LDLIBS)

test-codec: $(BUILD)/packet_codec_test
	./$(BUILD)/packet_codec_test

check-env:
	bash scripts/check_rdma_env.sh

clean:
	rm -rf $(BUILD)

# Dependency-light simulation build. No libibverbs, RNIC or privileged sockets
# are required. CMake provides the equivalent out-of-tree CTest build.
SIM_SOURCES := $(filter-out $(CORE)/Test/PDS_fulltest.cpp,$(PDS_SOURCES)) \
  $(CORE)/Network_Layer/PdsQueueTransport.cpp \
  $(CORE)/Network_Layer/PdsPacketCodec.cpp \
  $(CORE)/Network_Layer/UetWireCodec.cpp
SIM_OBJECTS := $(patsubst %.cpp,$(BUILD)/%.o,$(SIM_SOURCES))
SIM_TESTS := runtime_test memory_registry_test memory_key_test nscc_test nscc_integration_test fabric_test fabric_congestion_test packet_trimming_test uet_wire_test \
  pdc_ack_test peer_sequence_window_test pds_mpr_test pds_fault_test pds_recovery_test uud_delivery_test rud_window_test \
  pdc_lifecycle_test native_atomic_test context_reuse_test message_retirement_test addressing_test resource_lifecycle_test control_ack_test control_establishment_test target_close_test message_completion_test streaming_payload_test semantic_error_test unexpected_message_test \
  pds_allocation_test pds_simulation_test endpoint_test

$(BUILD)/libsoftue_protocol.a: $(SIM_OBJECTS)
	ar rcs $@ $^

define SIM_TEST_RULE
$(BUILD)/$(1): $(CORE)/Test/$(2) $(CORE_HEADERS) $(BUILD)/libsoftue_protocol.a
	$$(CXX) $$(CPPFLAGS) $$(CXXFLAGS) -I$$(CORE) $$< $$(BUILD)/libsoftue_protocol.a -o $$@ $$(LDFLAGS) $$(LDLIBS)
endef
$(eval $(call SIM_TEST_RULE,runtime_test,RuntimeTest.cpp))
$(eval $(call SIM_TEST_RULE,memory_registry_test,MemoryRegistryTest.cpp))
$(eval $(call SIM_TEST_RULE,memory_key_test,MemoryKeyTest.cpp))
$(eval $(call SIM_TEST_RULE,nscc_test,NsccTest.cpp))
$(eval $(call SIM_TEST_RULE,nscc_integration_test,NsccIntegrationTest.cpp))
$(eval $(call SIM_TEST_RULE,fabric_test,FabricTest.cpp))
$(eval $(call SIM_TEST_RULE,fabric_congestion_test,FabricCongestionTest.cpp))
$(eval $(call SIM_TEST_RULE,packet_trimming_test,PacketTrimmingTest.cpp))
$(eval $(call SIM_TEST_RULE,uet_wire_test,UetWireCodecTest.cpp))
$(eval $(call SIM_TEST_RULE,pdc_ack_test,PdcAckTest.cpp))
$(eval $(call SIM_TEST_RULE,peer_sequence_window_test,PeerSequenceWindowTest.cpp))
$(eval $(call SIM_TEST_RULE,pds_mpr_test,PdsMprTest.cpp))
$(eval $(call SIM_TEST_RULE,pds_fault_test,PdsFaultTest.cpp))
$(eval $(call SIM_TEST_RULE,pds_recovery_test,PdsRecoveryTest.cpp))
$(eval $(call SIM_TEST_RULE,uud_delivery_test,UudDeliveryTest.cpp))
$(eval $(call SIM_TEST_RULE,rud_window_test,RudWindowTest.cpp))
$(eval $(call SIM_TEST_RULE,pdc_lifecycle_test,PdcLifecycleTest.cpp))
$(eval $(call SIM_TEST_RULE,native_atomic_test,NativeAtomicTest.cpp))
$(eval $(call SIM_TEST_RULE,context_reuse_test,ContextReuseTest.cpp))
$(eval $(call SIM_TEST_RULE,message_retirement_test,MessageRetirementTest.cpp))
$(eval $(call SIM_TEST_RULE,addressing_test,AddressingTest.cpp))
$(eval $(call SIM_TEST_RULE,resource_lifecycle_test,ResourceLifecycleTest.cpp))
$(eval $(call SIM_TEST_RULE,control_ack_test,ControlAckTest.cpp))
$(eval $(call SIM_TEST_RULE,control_establishment_test,ControlEstablishmentTest.cpp))
$(eval $(call SIM_TEST_RULE,target_close_test,TargetCloseTest.cpp))
$(eval $(call SIM_TEST_RULE,message_completion_test,MessageCompletionTest.cpp))
$(eval $(call SIM_TEST_RULE,streaming_payload_test,StreamingPayloadTest.cpp))
$(eval $(call SIM_TEST_RULE,semantic_error_test,SemanticErrorTest.cpp))
$(eval $(call SIM_TEST_RULE,unexpected_message_test,UnexpectedMessageTest.cpp))
$(eval $(call SIM_TEST_RULE,pds_allocation_test,PdsAllocationTest.cpp))
$(eval $(call SIM_TEST_RULE,pds_simulation_test,PdsSimulationTest.cpp))
$(eval $(call SIM_TEST_RULE,endpoint_test,EndpointTest.cpp))

.PHONY: simulation test-sim test-scenarios test-requirements test
$(BUILD)/softue_sim: $(CORE)/Runtime/SimMain.cpp $(CORE_HEADERS) $(BUILD)/libsoftue_protocol.a
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(CORE) $< $(BUILD)/libsoftue_protocol.a -o $@ $(LDFLAGS) $(LDLIBS)

simulation: $(BUILD)/softue_sim $(addprefix $(BUILD)/,$(SIM_TESTS))
test-sim: simulation
	@set -e; for name in $(SIM_TESTS); do \
	  ./$(BUILD)/$$name > $(BUILD)/$$name.log 2>&1 || { tail -n 30 $(BUILD)/$$name.log; exit 1; }; \
	  echo "PASS $$name"; \
	done
test-scenarios: $(BUILD)/softue_sim
	python3 scripts/test_simulation.py --binary $(BUILD)/softue_sim

test-requirements:
	python3 scripts/check_requirements.py --output $(BUILD)/conformance.json

test: test-sim test-scenarios test-codec test-ses-payload test-pds-loopback test-pds-process-loopback test-interactive-udp test-requirements
