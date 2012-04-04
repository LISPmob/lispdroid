# Android makefile for lispd module

ifneq ($(TARGET_SIMULATOR),true)
LOCAL_PATH:= $(call my-dir)

etc_dir := $(TARGET_OUT)/etc/lispd

subdirs := $(addprefix $(LOCAL_PATH)/,$(addsuffix /Android.mk, \
	confuse/ lispmanager/ \
))

include $(CLEAR_VARS)
LOCAL_SRC_FILES = cmdline.c lispd.c lispd_config.c lispd_syslog.c \
                  lispd_util.c lispd_netlink.c lispd_map_register.c \
                  patricia/patricia.c lispd_map_request.c cksum.c \
                  lispd_events.c lispd_db.c lispd_map_reply.c \
                  lispd_timers.c lispd_if.c tables.c lispd_tuntap.c \
                  lispd_encap.c
LOCAL_C_FLAGS += -g
LOCAL_C_INCLUDES := external/openssl/include/
LOCAL_STATIC_LIBRARIES := libconfuse
LOCAL_SHARED_LIBRARIES := libcutils libssl libcrypto
LOCAL_MODULE = lispd
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)

include $(subdirs) 
endif
