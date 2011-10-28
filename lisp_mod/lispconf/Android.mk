# Android makefile for lispd module

ifneq ($(TARGET_SIMULATOR),true)
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES = cmdline.c lispconf.c
LOCAL_C_FLAGS += -g -O0
LOCAL_MODULE = lispconf
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)
endif
