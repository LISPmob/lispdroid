#!/bin/sh
adb root
sleep 5
adb shell mount -o rw,remount /dev/block/mtdblock3 /system/
adb push ./lispd /system/bin/lispd
adb push ./lisp.ko /system/lib/modules/lisp.ko
adb push ./lispconf /system/bin/lispconf
adb push ./lig /system/bin/lig
adb push ./lispmanager /system/bin/lispmanager
adb push ./busybox /system/bin/busybox
adb shell chmod 4755 /system/bin/lispmanager
adb shell chmod 4755 /system/bin/busybox
adb install -r ./lispmonApp.apk
