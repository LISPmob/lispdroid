cmd_console-tools/fgconsole.o := arm-none-linux-gnueabi-gcc -Wp,-MD,console-tools/.fgconsole.o.d   -std=gnu99 -Iinclude -Ilibbb  -include include/autoconf.h -D_GNU_SOURCE -DNDEBUG -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D"BB_VER=KBUILD_STR(1.18.4)" -DBB_BT=AUTOCONF_TIMESTAMP --static -Wall -Wshadow -Wwrite-strings -Wundef -Wstrict-prototypes -Wunused -Wunused-parameter -Wunused-function -Wunused-value -Wmissing-prototypes -Wmissing-declarations -Wdeclaration-after-statement -Wold-style-definition -fno-builtin-strlen -finline-limit=0 -fomit-frame-pointer -ffunction-sections -fdata-sections -fno-guess-branch-probability -funsigned-char -static-libgcc -falign-functions=1 -falign-jumps=1 -falign-labels=1 -falign-loops=1 -Os     -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(fgconsole)"  -D"KBUILD_MODNAME=KBUILD_STR(fgconsole)" -c -o console-tools/fgconsole.o console-tools/fgconsole.c

deps_console-tools/fgconsole.o := \
  console-tools/fgconsole.c \
  include/libbb.h \
    $(wildcard include/config/selinux.h) \
    $(wildcard include/config/locale/support.h) \
    $(wildcard include/config/feature/shadowpasswds.h) \
    $(wildcard include/config/use/bb/shadow.h) \
    $(wildcard include/config/use/bb/pwd/grp.h) \
    $(wildcard include/config/lfs.h) \
    $(wildcard include/config/feature/buffers/go/on/stack.h) \
    $(wildcard include/config/feature/buffers/go/in/bss.h) \
    $(wildcard include/config/feature/ipv6.h) \
    $(wildcard include/config/feature/seamless/lzma.h) \
    $(wildcard include/config/feature/seamless/bz2.h) \
    $(wildcard include/config/feature/seamless/gz.h) \
    $(wildcard include/config/feature/seamless/z.h) \
    $(wildcard include/config/feature/check/names.h) \
    $(wildcard include/config/feature/utmp.h) \
    $(wildcard include/config/feature/prefer/applets.h) \
    $(wildcard include/config/busybox/exec/path.h) \
    $(wildcard include/config/long/opts.h) \
    $(wildcard include/config/feature/getopt/long.h) \
    $(wildcard include/config/feature/pidfile.h) \
    $(wildcard include/config/feature/syslog.h) \
    $(wildcard include/config/feature/individual.h) \
    $(wildcard include/config/echo.h) \
    $(wildcard include/config/printf.h) \
    $(wildcard include/config/test.h) \
    $(wildcard include/config/kill.h) \
    $(wildcard include/config/chown.h) \
    $(wildcard include/config/ls.h) \
    $(wildcard include/config/xxx.h) \
    $(wildcard include/config/route.h) \
    $(wildcard include/config/feature/hwib.h) \
    $(wildcard include/config/desktop.h) \
    $(wildcard include/config/feature/crond/d.h) \
    $(wildcard include/config/use/bb/crypt.h) \
    $(wildcard include/config/feature/adduser/to/group.h) \
    $(wildcard include/config/feature/del/user/from/group.h) \
    $(wildcard include/config/ioctl/hex2str/error.h) \
    $(wildcard include/config/feature/editing.h) \
    $(wildcard include/config/feature/editing/history.h) \
    $(wildcard include/config/feature/editing/savehistory.h) \
    $(wildcard include/config/feature/tab/completion.h) \
    $(wildcard include/config/feature/username/completion.h) \
    $(wildcard include/config/feature/editing/vi.h) \
    $(wildcard include/config/pmap.h) \
    $(wildcard include/config/feature/show/threads.h) \
    $(wildcard include/config/feature/ps/additional/columns.h) \
    $(wildcard include/config/feature/topmem.h) \
    $(wildcard include/config/feature/top/smp/process.h) \
    $(wildcard include/config/killall.h) \
    $(wildcard include/config/pgrep.h) \
    $(wildcard include/config/pkill.h) \
    $(wildcard include/config/pidof.h) \
    $(wildcard include/config/sestatus.h) \
    $(wildcard include/config/feature/mtab/support.h) \
    $(wildcard include/config/feature/devfs.h) \
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
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/ctype.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/types.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../lib/gcc/arm-none-linux-gnueabi/4.2.3/include/stddef.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/typesizes.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/xlocale.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/dirent.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/dirent.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/errno.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/errno.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/linux/errno.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/asm/errno.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/asm-generic/errno.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/asm-generic/errno-base.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/fcntl.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/fcntl.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/types.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/time.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/select.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/select.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/sigset.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/time.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/sysmacros.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/pthreadtypes.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/uio.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/stat.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/stat.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/inttypes.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/stdint.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/wchar.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/netdb.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/netinet/in.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/socket.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/uio.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/socket.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/sockaddr.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/asm/socket.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/asm/sockios.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/in.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/rpc/netdb.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/siginfo.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/netdb.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/setjmp.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/setjmp.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/signal.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/signum.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/sigaction.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/sigcontext.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/asm/sigcontext.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/sigstack.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/ucontext.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/procfs.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/time.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/user.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/sigthread.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/stdio.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/libio.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/_G_config.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/wchar.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/gconv.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../lib/gcc/arm-none-linux-gnueabi/4.2.3/include/stdarg.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/sys_errlist.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/stdlib.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/waitflags.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/waitstatus.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/alloca.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/string.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/poll.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/poll.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/ioctl.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/ioctls.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/asm/ioctls.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/asm/ioctl.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/asm-generic/ioctl.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/ioctl-types.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/ttydefaults.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/mman.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/mman.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/wait.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/resource.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/resource.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/termios.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/termios.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/unistd.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/posix_opt.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/environments.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/confname.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/getopt.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/param.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/linux/param.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/asm/param.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/mntent.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/paths.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/sys/statfs.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/bits/statfs.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/pwd.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/grp.h \
  /home/chris/CodeSourcery/Sourcery_G++_Lite/bin/../arm-none-linux-gnueabi/libc/usr/include/arpa/inet.h \
  include/pwd_.h \
  include/grp_.h \
  include/shadow_.h \
  include/xatonum.h \

console-tools/fgconsole.o: $(deps_console-tools/fgconsole.o)

$(deps_console-tools/fgconsole.o):
