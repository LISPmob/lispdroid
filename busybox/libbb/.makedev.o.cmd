cmd_libbb/makedev.o := arm-none-linux-gnueabi-gcc -Wp,-MD,libbb/.makedev.o.d   -std=gnu99 -Iinclude -Ilibbb  -include include/autoconf.h -D_GNU_SOURCE -DNDEBUG -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D"BB_VER=KBUILD_STR(1.18.4)" -DBB_BT=AUTOCONF_TIMESTAMP --static -Wall -Wshadow -Wwrite-strings -Wundef -Wstrict-prototypes -Wunused -Wunused-parameter -Wunused-function -Wunused-value -Wmissing-prototypes -Wmissing-declarations -Wdeclaration-after-statement -Wold-style-definition -fno-builtin-strlen -finline-limit=0 -fomit-frame-pointer -ffunction-sections -fdata-sections -fno-guess-branch-probability -funsigned-char -static-libgcc -falign-functions=1 -falign-jumps=1 -falign-labels=1 -falign-loops=1 -Os     -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(makedev)"  -D"KBUILD_MODNAME=KBUILD_STR(makedev)" -c -o libbb/makedev.o libbb/makedev.c

deps_libbb/makedev.o := \
  libbb/makedev.c \
  include/platform.h \
    $(wildcard include/config/werror.h) \
    $(wildcard include/config/big/endian.h) \
    $(wildcard include/config/little/endian.h) \
    $(wildcard include/config/nommu.h) \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../lib/gcc/arm-none-linux-gnueabi/4.2.3/include-fixed/limits.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../lib/gcc/arm-none-linux-gnueabi/4.2.3/include-fixed/syslimits.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/limits.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/features.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/predefs.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/cdefs.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/wordsize.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/gnu/stubs.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/posix1_lim.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/local_lim.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/linux/limits.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/posix2_lim.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/xopen_lim.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/stdio_lim.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/byteswap.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/byteswap.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/endian.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/endian.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../lib/gcc/arm-none-linux-gnueabi/4.2.3/include/stdbool.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/sysmacros.h \

libbb/makedev.o: $(deps_libbb/makedev.o)

$(deps_libbb/makedev.o):
