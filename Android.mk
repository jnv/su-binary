LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := su
LOCAL_SRC_FILES := su.c


LOCAL_SHARED_LIBRARIES := liblog

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)

include $(BUILD_EXECUTABLE)
