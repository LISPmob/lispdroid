#!/bin/sh
rm -rf releasedir
mkdir releasedir
cp ../../out/target/product/passion/obj/EXECUTABLES/lispd_intermediates/LINKED/lispd releasedir
cp lispd.conf releasedir
cp ../lisp_mod/lisp.ko releasedir
cp ../../out/target/product/passion/obj/EXECUTABLES/lispconf_intermediates/LINKED/lispconf releasedir
cp ../../out/target/product/passion/obj/EXECUTABLES/lig_intermediates/LINKED/lig releasedir
cp ../../out/target/product/passion/obj/EXECUTABLES/lispmanager_intermediates/LINKED/lispmanager releasedir
cp ~chris/workspace/lispmonApp/bin/lispmonApp.apk releasedir
cp release_install.sh releasedir/install.sh
