#!/bin/sh

bblink () {
  if [ ! -e $1 ]; then
      ln -s busybox $1
  fi
}

mount -o rw,remount /system
cd /system/bin

if [ ! -e busybox ]; then
  cat /sdcard/busybox > busybox
  chmod 4755 busybox
fi
bblink grep
bblink more
bblink tail
bblink find
bblink which
bblink wget
bblink killall
busybox mv /sdcard/lispd /system/bin/
busybox mv /sdcard/lispconf /system/bin/
busybox mv /sdcard/lispmanager /system/bin/
chown root /system/bin/lispd /system/bin/lispconf /system/bin/lispmanager
chmod 755 /system/bin/lispd /system/bin/lispconf
chmod 4755 /system/bin/lispmanager
exit 0
