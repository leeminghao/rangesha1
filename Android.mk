LOCAL_PATH := $(call my-dir)

# host
include $(CLEAR_VARS)

LOCAL_SRC_FILES := rangesha1.c
LOCAL_STATIC_LIBRARIES := libmincrypt libcutils
LOCAL_C_INCLUDES := system/core/include
LOCAL_MODULE := rangesha1

include $(BUILD_HOST_EXECUTABLE)

# target
include $(CLEAR_VARS)

LOCAL_SRC_FILES := rangesha1.c
LOCAL_STATIC_LIBRARIES := libc libmincrypt libcutils
LOCAL_C_INCLUDES := system/core/include
LOCAL_MODULE := rangesha1
LOCAL_FORCE_STATIC_EXECUTABLE := true

include $(BUILD_EXECUTABLE)
