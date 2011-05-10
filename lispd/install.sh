#!/bin/sh
adb push ../../out/target/product/passion/obj/EXECUTABLES/lispd_intermediates/LINKED/lispd /system/bin/lispd
cp ../../out/target/product/passion/obj/EXECUTABLES/lispd_intermediates/LINKED/lispd .
adb push lispd.conf /sdcard/lispd.conf
adb push ../../out/target/product/passion/obj/EXECUTABLES/lispconf_intermediates/LINKED/lispconf /system/bin/lispconf
adb push ../../out/target/product/passion/obj/EXECUTABLES/lig_intermediates/LINKED/lig /system/bin/lig
adb push ../../out/target/product/passion/obj/EXECUTABLES/lispmanager_intermediates/LINKED/lispmanager /system/bin/lispmanager
adb shell chmod 4755 /system/bin/lispmanager
