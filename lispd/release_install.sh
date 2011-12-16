#!/bin/sh

zadb () {
    adb $*
    s=$?
    if [ $s = 0 ]; then return 0
    fi
    echo "failed: adb $*"
    exit $s
}

zadb root
sleep 5
zadb shell mount -o rw,remount /system
zadb push ./lispd /system/bin/lispd
zadb push ./lisp.ko /system/modules/lisp.ko
zadb push ./lispconf /system/bin/lispconf
zadb push ./lispmanager /system/bin/lispmanager
zadb push ./busybox /system/bin/busybox
zadb shell chmod 4755 /system/bin/lispmanager
zadb shell chmod 4755 /system/bin/busybox
zadb install -r ./lispmonApp.apk
