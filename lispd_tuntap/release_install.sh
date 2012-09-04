#!/bin/sh

zadb () {
    adb $*
    s=$?
    if [ $s = 0 ]; then return 0
    fi
    echo "failed: adb $*"
    exit $s
}

zadb root | grep -q "cannot run as root"
if [ $? != 0 ]; then
    sleep 5
    zadb shell mount -o rw,remount /system
    zadb push ./lispd /system/bin/lispd
    zadb push ./lispconf /system/bin/lispconf
    zadb push ./lispmanager /system/bin/lispmanager
    zadb push ./busybox /system/bin/busybox
    zadb shell chmod 755 /system/bin/lispd
    zadb shell chmod 755 /system/bin/lispconf
    zadb shell chmod 4755 /system/bin/lispmanager
    zadb shell chmod 4755 /system/bin/busybox
else
    sleep 5
    zadb push ./lispd /sdcard/
    zadb push ./lispconf /sdcard/
    zadb push ./lispmanager /sdcard/
    zadb push ./busybox /sdcard/
    zadb push ./inhelper.sh /sdcard/
    zadb shell "su -c 'sh -x /sdcard/inhelper.sh'"
fi
zadb install -r ./lispmonApp.apk
