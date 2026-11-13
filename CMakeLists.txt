cmake_minimum_required(VERSION 3.16)
project(SoftUE VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(SOFTUE_ENABLE_RDMA "Build the legacy InfiniBand RC adapter" OFF)
option(SOFTUE_ENABLE_SANITIZERS "Enable address and undefined-behavior sanitizers" OFF)
option(SOFTUE_ENABLE_LIBFABRIC "Build the experimental manual-progress softue provider" OFF)
set(SOFTUE_PROVIDER_LIBFABRIC_ROOT "" CACHE PATH "Installed libfabric 2.0 prefix for the softue provider")
set(SOFTUE_REFERENCE_ROOT "" CACHE PATH "Pinned uet-ref-prov checkout for optional differential tests")
set(SOFTUE_LIBFABRIC_ROOT "" CACHE PATH "Built libfabric 2.0 source tree used by the reference provider")
find_package(Threads REQUIRED)
include(CTest)

if(SOFTUE_ENABLE_SANITIZERS)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

set(CORE ${CMAKE_CURRENT_SOURCE_DIR}/UET/src)
add_library(softue_protocol STATIC
  ${CORE}/PDS/PDC/PDC.cpp
  ${CORE}/PDS/PDC/Probe.cpp
  ${CORE}/PDS/PDC/TransmitTiming.cpp
  ${CORE}/PDS/PDC/OrderedAcknowledgment.cpp
  ${CORE}/PDS/PDC/NegativeAcknowledgment.cpp
  ${CORE}/PDS/PDC/IPDC.cpp
  ${CORE}/PDS/PDC/TPDC.cpp
  ${CORE}/PDS/PDC/RTOTimer/RTOTimer.cpp
  ${CORE}/Network_Layer/UDP_Network_Layer.cpp)
target_include_directories(softue_protocol PUBLIC ${CORE})
target_link_libraries(softue_protocol PUBLIC Threads::Threads)

add_library(softue_message STATIC
  ${CORE}/Network_Layer/PacketCodec.cpp
  ${CORE}/Network_Layer/PdsPacketCodec.cpp
  ${CORE}/Network_Layer/UetWireCodec.cpp
  ${CORE}/Network_Layer/PdsQueueTransport.cpp
  ${CORE}/Network_Layer/UdpChannel.cpp
  ${CORE}/PDS/MessageStream.cpp
  ${CORE}/SES/MessageEndpoint.cpp)
target_include_directories(softue_message PUBLIC ${CORE})
target_link_libraries(softue_message PUBLIC Threads::Threads)
if(SOFTUE_ENABLE_RDMA)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(IBVERBS REQUIRED IMPORTED_TARGET libibverbs)
  target_sources(softue_message PRIVATE ${CORE}/Network_Layer/RdmaChannel.cpp)
  target_link_libraries(softue_message PUBLIC PkgConfig::IBVERBS)
  target_compile_definitions(softue_message PUBLIC SOFTUE_HAS_RDMA=1)
else()
  target_compile_definitions(softue_message PUBLIC SOFTUE_HAS_RDMA=0)
endif()

add_executable(rdma_message_test ${CORE}/Test/RdmaMessageTest.cpp)
target_link_libraries(rdma_message_test PRIVATE softue_message)
add_executable(softue_sim ${CORE}/Runtime/SimMain.cpp)
target_link_libraries(softue_sim PRIVATE softue_protocol softue_message)

if(SOFTUE_ENABLE_LIBFABRIC)
  find_path(SOFTUE_FABRIC_INCLUDE rdma/providers/fi_prov.h HINTS ${SOFTUE_PROVIDER_LIBFABRIC_ROOT}/include REQUIRED)
  find_library(SOFTUE_FABRIC_LIBRARY fabric HINTS ${SOFTUE_PROVIDER_LIBFABRIC_ROOT}/lib ${SOFTUE_PROVIDER_LIBFABRIC_ROOT}/src/.libs REQUIRED)
  set_target_properties(softue_protocol softue_message PROPERTIES POSITION_INDEPENDENT_CODE ON)
  add_library(softue_fabric MODULE ${CORE}/Provider/SoftueProvider.cpp)
  target_include_directories(softue_fabric PRIVATE ${SOFTUE_FABRIC_INCLUDE})
  target_link_libraries(softue_fabric PRIVATE softue_protocol softue_message ${SOFTUE_FABRIC_LIBRARY})
  set_target_properties(softue_fabric PROPERTIES OUTPUT_NAME softue-fi)
endif()

if(BUILD_TESTING)
  function(softue_test name source)
    add_executable(${name} ${CORE}/Test/${source})
    target_link_libraries(${name} PRIVATE softue_protocol softue_message)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
      target_compile_options(${name} PRIVATE -UNDEBUG)
    endif()
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT 60)
  endfunction()
  softue_test(runtime_test RuntimeTest.cpp)
  softue_test(realtime_late_progress_test RealtimeLateProgressTest.cpp)
  softue_test(retry_timing_test RetryTimingTest.cpp)
  softue_test(retry_limit_test RetryLimitTest.cpp)
  softue_test(initial_sequence_test InitialSequenceTest.cpp)
  softue_test(syn_range_test SynRangeTest.cpp)
  softue_test(receive_admission_test ReceiveAdmissionTest.cpp)
  softue_test(negative_acknowledgment_test NegativeAcknowledgmentTest.cpp)
  softue_test(memory_registry_test MemoryRegistryTest.cpp)
  softue_test(local_placement_scope_test LocalPlacementScopeTest.cpp)
  softue_test(memory_key_test MemoryKeyTest.cpp)
  softue_test(nscc_test NsccTest.cpp)
  softue_test(nscc_integration_test NsccIntegrationTest.cpp)
  softue_test(nscc_lifecycle_test NsccLifecycleTest.cpp)
  softue_test(fabric_test FabricTest.cpp)
  softue_test(fabric_congestion_test FabricCongestionTest.cpp)
  softue_test(packet_trimming_test PacketTrimmingTest.cpp)
  softue_test(uet_wire_test UetWireCodecTest.cpp)
  softue_test(ses_reserved_fields_test SesReservedFieldsTest.cpp)
  softue_test(pds_reserved_fields_test PdsReservedFieldsTest.cpp)
  softue_test(pds_invalid_type_test PdsInvalidTypeTest.cpp)
  softue_test(pds_traffic_class_test PdsTrafficClassTest.cpp)
  softue_test(ordered_acknowledgment_test OrderedAcknowledgmentTest.cpp)
  softue_test(udp_encapsulation_test UdpEncapsulationTest.cpp)
  softue_test(network_defaults_test NetworkDefaultsTest.cpp)
  softue_test(pdc_ack_test PdcAckTest.cpp)
  softue_test(peer_sequence_window_test PeerSequenceWindowTest.cpp)
  softue_test(pds_mpr_test PdsMprTest.cpp)
  softue_test(psn_range_configuration_test PsnRangeConfigurationTest.cpp)
  softue_test(selective_acknowledgment_test SelectiveAcknowledgmentTest.cpp)
  softue_test(pds_feedback_test PdsFeedbackTest.cpp)
  softue_test(pds_probe_test PdsProbeTest.cpp)
  softue_test(mac_timing_test MacTimingTest.cpp)
  softue_test(pds_fault_test PdsFaultTest.cpp)
  softue_test(pds_recovery_test PdsRecoveryTest.cpp)
  softue_test(uud_delivery_test UudDeliveryTest.cpp)
  softue_test(rud_window_test RudWindowTest.cpp)
  softue_test(pdc_lifecycle_test PdcLifecycleTest.cpp)
  softue_test(native_atomic_test NativeAtomicTest.cpp)
  softue_test(fetching_atomic_value_test FetchingAtomicValueTest.cpp)
  softue_test(native_fetching_atomic_test NativeFetchingAtomicTest.cpp)
  softue_test(zero_atomic_test ZeroAtomicTest.cpp)
  set_tests_properties(native_fetching_atomic_test PROPERTIES TIMEOUT 180)
  softue_test(context_reuse_test ContextReuseTest.cpp)
  softue_test(message_retirement_test MessageRetirementTest.cpp)
  softue_test(addressing_test AddressingTest.cpp)
  softue_test(resource_lifecycle_test ResourceLifecycleTest.cpp)
  softue_test(control_ack_test ControlAckTest.cpp)
  softue_test(control_establishment_test ControlEstablishmentTest.cpp)
  softue_test(target_close_test TargetCloseTest.cpp)
  softue_test(message_completion_test MessageCompletionTest.cpp)
  softue_test(send_header_data_test SendHeaderDataTest.cpp)
  softue_test(streaming_payload_test StreamingPayloadTest.cpp)
  softue_test(streaming_read_test StreamingReadTest.cpp)
  # Boundary reports reject a stale binary instead of assigning current HEAD
  # to an executable built from an earlier source tree.
  execute_process(COMMAND git rev-parse HEAD WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE SOFTUE_READ_BUILD_COMMIT OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET
    RESULT_VARIABLE SOFTUE_READ_REVISION_RESULT)
  execute_process(COMMAND git status --porcelain --untracked-files=normal WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE SOFTUE_READ_BUILD_STATUS ERROR_QUIET RESULT_VARIABLE SOFTUE_READ_STATUS_RESULT)
  if(NOT SOFTUE_READ_REVISION_RESULT EQUAL 0 OR NOT SOFTUE_READ_BUILD_COMMIT MATCHES "^[0-9a-f]+$")
    set(SOFTUE_READ_BUILD_COMMIT "unknown")
  endif()
  set(SOFTUE_READ_BUILD_DIRTY 1)
  if(SOFTUE_READ_REVISION_RESULT EQUAL 0 AND SOFTUE_READ_STATUS_RESULT EQUAL 0 AND SOFTUE_READ_BUILD_STATUS STREQUAL "")
    set(SOFTUE_READ_BUILD_DIRTY 0)
  endif()
  target_compile_definitions(streaming_read_test PRIVATE
    SOFTUE_READ_BUILD_COMMIT="${SOFTUE_READ_BUILD_COMMIT}" SOFTUE_READ_BUILD_DIRTY=${SOFTUE_READ_BUILD_DIRTY})
  softue_test(semantic_error_test SemanticErrorTest.cpp)
  softue_test(guaranteed_error_test GuaranteedErrorTest.cpp)
  softue_test(unexpected_message_test UnexpectedMessageTest.cpp)
  add_executable(realtime_endpoint_peer ${CORE}/Test/RealtimeEndpointPeer.cpp)
  target_link_libraries(realtime_endpoint_peer PRIVATE softue_protocol softue_message)
  set_tests_properties(message_retirement_test PROPERTIES TIMEOUT 600)
  softue_test(pds_allocation_test PdsAllocationTest.cpp)
  softue_test(pdc_mapping_test PdcMappingTest.cpp)
  softue_test(pds_simulation_test PdsSimulationTest.cpp)
  softue_test(endpoint_test EndpointTest.cpp)
  softue_test(read_ack_data_test ReadAckDataTest.cpp)
  softue_test(return_data_transport_test ReturnDataTransportTest.cpp)
  softue_test(native_read_test NativeReadTest.cpp)
  set_tests_properties(native_read_test PROPERTIES TIMEOUT 600)
  softue_test(read_early_acceptance_test ReadEarlyAcceptanceTest.cpp)
  softue_test(read_large_ack_test ReadLargeAckTest.cpp)
  softue_test(packet_codec_test PacketCodecTest.cpp)
  softue_test(ses_payload_test SesPayloadIntegrationTest.cpp)
  softue_test(pds_runtime_loopback_test PdsRuntimeLoopbackTest.cpp)
  softue_test(pds_process_loopback_test PdsProcessLoopbackTest.cpp)
  softue_test(PDS_fulltest PDS_fulltest.cpp)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  if(SOFTUE_ENABLE_LIBFABRIC)
    enable_language(C)
    softue_test(libfabric_local_registration_test LibfabricLocalRegistrationTest.cpp)
    target_include_directories(libfabric_local_registration_test PRIVATE ${SOFTUE_FABRIC_INCLUDE})
    target_link_libraries(libfabric_local_registration_test PRIVATE ${SOFTUE_FABRIC_LIBRARY})
    add_dependencies(libfabric_local_registration_test softue_fabric)
    set_tests_properties(libfabric_local_registration_test PROPERTIES TIMEOUT 40
      ENVIRONMENT "FI_PROVIDER=softue;FI_PROVIDER_PATH=$<TARGET_FILE_DIR:softue_fabric>")
    softue_test(libfabric_atomic_return_test LibfabricAtomicReturnTest.cpp)
    target_include_directories(libfabric_atomic_return_test PRIVATE ${SOFTUE_FABRIC_INCLUDE})
    target_link_libraries(libfabric_atomic_return_test PRIVATE ${SOFTUE_FABRIC_LIBRARY})
    add_dependencies(libfabric_atomic_return_test softue_fabric)
    set_tests_properties(libfabric_atomic_return_test PROPERTIES TIMEOUT 120
      ENVIRONMENT "FI_PROVIDER=softue;FI_PROVIDER_PATH=$<TARGET_FILE_DIR:softue_fabric>")
    softue_test(libfabric_read_test LibfabricReadTest.cpp)
    target_include_directories(libfabric_read_test PRIVATE ${SOFTUE_FABRIC_INCLUDE})
    target_link_libraries(libfabric_read_test PRIVATE ${SOFTUE_FABRIC_LIBRARY})
    add_dependencies(libfabric_read_test softue_fabric)
    set_tests_properties(libfabric_read_test PROPERTIES TIMEOUT 60
      ENVIRONMENT "FI_PROVIDER=softue;FI_PROVIDER_PATH=$<TARGET_FILE_DIR:softue_fabric>")
    softue_test(libfabric_mode_selection_test LibfabricModeSelectionTest.cpp)
    target_include_directories(libfabric_mode_selection_test PRIVATE ${SOFTUE_FABRIC_INCLUDE})
    target_link_libraries(libfabric_mode_selection_test PRIVATE ${SOFTUE_FABRIC_LIBRARY})
    add_dependencies(libfabric_mode_selection_test softue_fabric)
    set_tests_properties(libfabric_mode_selection_test PROPERTIES TIMEOUT 40
      ENVIRONMENT "FI_PROVIDER=softue;FI_PROVIDER_PATH=$<TARGET_FILE_DIR:softue_fabric>")
    softue_test(libfabric_inject_test LibfabricInjectTest.cpp)
    target_include_directories(libfabric_inject_test PRIVATE ${SOFTUE_FABRIC_INCLUDE})
    target_link_libraries(libfabric_inject_test PRIVATE ${SOFTUE_FABRIC_LIBRARY})
    add_dependencies(libfabric_inject_test softue_fabric)
    set_tests_properties(libfabric_inject_test PROPERTIES TIMEOUT 40
      ENVIRONMENT "FI_PROVIDER=softue;FI_PROVIDER_PATH=$<TARGET_FILE_DIR:softue_fabric>")
    add_executable(libfabric_event_queue_test ${CORE}/Test/LibfabricEventQueueTest.c)
    target_include_directories(libfabric_event_queue_test PRIVATE ${SOFTUE_FABRIC_INCLUDE})
    target_link_libraries(libfabric_event_queue_test PRIVATE ${SOFTUE_FABRIC_LIBRARY})
    add_dependencies(libfabric_event_queue_test softue_fabric)
    add_test(NAME libfabric_event_queue_test COMMAND libfabric_event_queue_test)
    set_tests_properties(libfabric_event_queue_test PROPERTIES TIMEOUT 20
      ENVIRONMENT "FI_PROVIDER=softue;FI_PROVIDER_PATH=$<TARGET_FILE_DIR:softue_fabric>")
    add_executable(libfabric_provider_peer ${CORE}/Test/LibfabricProviderPeer.c)
    target_include_directories(libfabric_provider_peer PRIVATE ${SOFTUE_FABRIC_INCLUDE})
    target_link_libraries(libfabric_provider_peer PRIVATE ${SOFTUE_FABRIC_LIBRARY})
    add_test(NAME libfabric_provider_processes COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_libfabric_provider.py
      --binary $<TARGET_FILE:libfabric_provider_peer> --provider-directory $<TARGET_FILE_DIR:softue_fabric>)
    set_tests_properties(libfabric_provider_processes PROPERTIES TIMEOUT 40)
    add_executable(libfabric_datagram_peer ${CORE}/Test/LibfabricDatagramPeer.c)
    target_include_directories(libfabric_datagram_peer PRIVATE ${SOFTUE_FABRIC_INCLUDE})
    target_link_libraries(libfabric_datagram_peer PRIVATE ${SOFTUE_FABRIC_LIBRARY})
    add_test(NAME libfabric_datagram_processes COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_libfabric_provider.py
      --binary $<TARGET_FILE:libfabric_datagram_peer> --provider-directory $<TARGET_FILE_DIR:softue_fabric>)
    set_tests_properties(libfabric_datagram_processes PROPERTIES TIMEOUT 40)
    add_executable(libfabric_recovery_peer ${CORE}/Test/LibfabricRecoveryPeer.c)
    target_include_directories(libfabric_recovery_peer PRIVATE ${SOFTUE_FABRIC_INCLUDE})
    target_link_libraries(libfabric_recovery_peer PRIVATE ${SOFTUE_FABRIC_LIBRARY})
    add_test(NAME libfabric_recovery_processes COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_libfabric_provider.py
      --binary $<TARGET_FILE:libfabric_recovery_peer> --provider-directory $<TARGET_FILE_DIR:softue_fabric>)
    set_tests_properties(libfabric_recovery_processes PROPERTIES TIMEOUT 40 ENVIRONMENT "SOFTUE_RECOVERY_ORDERED=1")
    add_test(NAME libfabric_unordered_recovery_processes COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_libfabric_provider.py
      --binary $<TARGET_FILE:libfabric_recovery_peer> --provider-directory $<TARGET_FILE_DIR:softue_fabric>)
    set_tests_properties(libfabric_unordered_recovery_processes PROPERTIES TIMEOUT 40 ENVIRONMENT "SOFTUE_RECOVERY_ORDERED=0")
  endif()
  add_test(NAME realtime_endpoint_processes COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_realtime_endpoint.py --binary $<TARGET_FILE:realtime_endpoint_peer>)
  set_tests_properties(realtime_endpoint_processes PROPERTIES TIMEOUT 40)
  add_test(NAME interactive_udp COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_interactive_udp.py
    --binary $<TARGET_FILE:rdma_message_test>)
  set_tests_properties(interactive_udp PROPERTIES TIMEOUT 90)
  add_test(NAME simulation_scenarios COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_simulation.py --binary $<TARGET_FILE:softue_sim>)
  set_tests_properties(simulation_scenarios PROPERTIES TIMEOUT 180)
  add_test(NAME requirement_inventory COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_requirements.py)
  set_tests_properties(requirement_inventory PROPERTIES TIMEOUT 10)
  if(SOFTUE_REFERENCE_ROOT)
    enable_language(C)
    add_executable(reference_wire_oracle ${CORE}/Test/ReferenceWireOracle.c)
    target_compile_definitions(reference_wire_oracle PRIVATE _GNU_SOURCE)
    target_include_directories(reference_wire_oracle PRIVATE
      ${SOFTUE_REFERENCE_ROOT} ${SOFTUE_REFERENCE_ROOT}/util
      ${SOFTUE_REFERENCE_ROOT}/imp_shim ${SOFTUE_REFERENCE_ROOT}/nic_shim
      ${SOFTUE_REFERENCE_ROOT}/crypto
      ${SOFTUE_LIBFABRIC_ROOT} ${SOFTUE_LIBFABRIC_ROOT}/include)
    target_link_libraries(reference_wire_oracle PRIVATE
      ${SOFTUE_REFERENCE_ROOT}/libuet_fabric.so
      ${SOFTUE_LIBFABRIC_ROOT}/src/.libs/libfabric.so)
    add_executable(reference_wire_fixtures ${CORE}/Test/ReferenceWireFixtures.cpp)
    target_link_libraries(reference_wire_fixtures PRIVATE softue_message)
    add_test(NAME reference_wire_comparison COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_reference_wire.py
      --fixtures $<TARGET_FILE:reference_wire_fixtures>
      --oracle $<TARGET_FILE:reference_wire_oracle>)
    set_tests_properties(reference_wire_comparison PROPERTIES TIMEOUT 30)
    add_executable(reference_interop_target ${CORE}/Test/ReferenceInteropTarget.c)
    target_compile_definitions(reference_interop_target PRIVATE _GNU_SOURCE)
    target_include_directories(reference_interop_target PRIVATE
      ${SOFTUE_REFERENCE_ROOT} ${SOFTUE_REFERENCE_ROOT}/util
      ${SOFTUE_REFERENCE_ROOT}/imp_shim ${SOFTUE_REFERENCE_ROOT}/nic_shim
      ${SOFTUE_REFERENCE_ROOT}/crypto
      ${SOFTUE_LIBFABRIC_ROOT} ${SOFTUE_LIBFABRIC_ROOT}/include)
    target_link_libraries(reference_interop_target PRIVATE
      ${SOFTUE_REFERENCE_ROOT}/libuet_fabric.so
      ${SOFTUE_LIBFABRIC_ROOT}/src/.libs/libfabric.so)
    # Export the executable's test NIC entry point so the unchanged reference
    # shared library resolves its NIC initialization through this adapter.
    target_link_options(reference_interop_target PRIVATE -Wl,--export-dynamic)
    add_executable(reference_interop_peer ${CORE}/Test/ReferenceInteropPeer.cpp)
    target_link_libraries(reference_interop_peer PRIVATE softue_protocol softue_message)
    add_test(NAME reference_process_interop COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_reference_interop.py
      --reference $<TARGET_FILE:reference_interop_target> --peer $<TARGET_FILE:reference_interop_peer>)
    set_tests_properties(reference_process_interop PROPERTIES TIMEOUT 40)
  endif()
endif()
