#!/bin/sh

OUT_DIR="/home/chris/source/cyanogen/out/target/product/crespo/obj/EXECUTABLES"

adb push $OUT_DIR/lispd_intermediates/LINKED/lispd /system/bin/lispd
cp $OUT_DIR/lispd_intermediates/LINKED/lispd .
#adb push lispd.conf /sdcard/lispd.conf
adb push $OUT_DIR/lispconf_intermediates/LINKED/lispconf /system/bin/lispconf
adb push $OUT_DIR/lispmanager_intermediates/LINKED/lispmanager /system/bin/lispmanager
adb shell chmod 4755 /system/bin/lispmanager
