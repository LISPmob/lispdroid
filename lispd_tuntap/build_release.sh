#!/bin/sh
rm -rf releasedir
mkdir releasedir
cp ../../out/target/product/crespo/obj/EXECUTABLES/lispd_intermediates/LINKED/lispd releasedir
cp lispd.conf releasedir
cp ../lisp_mod/lisp.ko releasedir
cp ../../out/target/product/crespo/obj/EXECUTABLES/lispconf_intermediates/LINKED/lispconf releasedir
cp ../../out/target/product/crespo/obj/EXECUTABLES/lig_intermediates/LINKED/lig releasedir
cp ../../out/target/product/crespo/obj/EXECUTABLES/lispmanager_intermediates/LINKED/lispmanager releasedir
cp ../lispmonApptuntap/bin/classes/"LISP Monitor TUNTAP.apk" releasedir/lispmonApp.apk
cp release_install.sh releasedir/install.sh
cp ../busybox-1.18.4/busybox releasedir
cp ../../out/target/product/crespo/system.img releasedir
cp ../../out/target/product/crespo/boot.img releasedir
