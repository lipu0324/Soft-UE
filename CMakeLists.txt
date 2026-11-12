cmake_minimum_required(VERSION 3.16)
project(SoftUE VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(SOFTUE_ENABLE_RDMA "Build the legacy InfiniBand RC adapter" OFF)
option(SOFTUE_ENABLE_SANITIZERS "Enable address and undefined-behavior sanitizers" OFF)
find_package(Threads REQUIRED)
include(CTest)

if(SOFTUE_ENABLE_SANITIZERS)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

set(CORE ${CMAKE_CURRENT_SOURCE_DIR}/UET/src)
add_library(softue_protocol STATIC
  ${CORE}/PDS/PDC/PDC.cpp
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
  softue_test(memory_registry_test MemoryRegistryTest.cpp)
  softue_test(fabric_test FabricTest.cpp)
  softue_test(uet_wire_test UetWireCodecTest.cpp)
  softue_test(pdc_ack_test PdcAckTest.cpp)
  softue_test(pds_fault_test PdsFaultTest.cpp)
  softue_test(pds_allocation_test PdsAllocationTest.cpp)
  softue_test(pds_simulation_test PdsSimulationTest.cpp)
  softue_test(endpoint_test EndpointTest.cpp)
  softue_test(packet_codec_test PacketCodecTest.cpp)
  softue_test(ses_payload_test SesPayloadIntegrationTest.cpp)
  softue_test(pds_runtime_loopback_test PdsRuntimeLoopbackTest.cpp)
  softue_test(pds_process_loopback_test PdsProcessLoopbackTest.cpp)
  softue_test(PDS_fulltest PDS_fulltest.cpp)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
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
endif()
