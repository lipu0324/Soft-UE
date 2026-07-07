UET_SRC_ROOT ?= .

UET_CORE_RUNTIME_SOURCES := \
	$(UET_SRC_ROOT)/SES/SES_LinkShim.cpp \
	$(UET_SRC_ROOT)/SES/SES_RxPlacement.cpp \
	$(UET_SRC_ROOT)/SES/SES_Completion.cpp \
	$(UET_SRC_ROOT)/SES/SES_SendRetry.cpp \
	$(UET_SRC_ROOT)/PDS/PDS_Manager/PDSManager.cpp \
	$(UET_SRC_ROOT)/PDS/PDS_Manager/PDSManager_RxBinding.cpp \
	$(UET_SRC_ROOT)/PDS/PDS_Manager/PDSManager_RxRouter.cpp \
	$(UET_SRC_ROOT)/PDS/PDS_Manager/PDSManager_Allocator.cpp \
	$(UET_SRC_ROOT)/PDS/PDS_Manager/PDSManager_Reclaim.cpp \
	$(UET_SRC_ROOT)/PDS/PDC/PDC.cpp \
	$(UET_SRC_ROOT)/PDS/PDC/PDC_RudPlacement.cpp \
	$(UET_SRC_ROOT)/PDS/PDC/PDC_RudArrival.cpp \
	$(UET_SRC_ROOT)/PDS/PDC/PDC_RudUnexpected.cpp \
	$(UET_SRC_ROOT)/PDS/PDC/PDC_RudCompletion.cpp \
	$(UET_SRC_ROOT)/PDS/PDC/IPDC.cpp \
	$(UET_SRC_ROOT)/PDS/PDC/IPDC_State.cpp \
	$(UET_SRC_ROOT)/PDS/PDC/TPDC.cpp \
	$(UET_SRC_ROOT)/PDS/PDC/TPDC_State.cpp \
	$(UET_SRC_ROOT)/PDS/PDC/RTOTimer/RTOTimer.cpp \
	$(UET_SRC_ROOT)/Network_Layer/UDP_Network_Layer.cpp
