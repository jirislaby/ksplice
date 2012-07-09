AC_INIT([Ksplice], [0.9.9.1], [devel@ksplice.com])
AC_SUBST([KSPLICE_API_VERSION], [2])

AC_ARG_WITH([libbfd],
  [  --with-libbfd=FILE      path to libbfd.a],
  [ac_libbfd=$withval],
  [ac_libbfd=NONE])

AC_ARG_WITH([libiberty],
  [  --with-libiberty=FILE   path to libiberty.a],
  [ac_libiberty=$withval],
  [ac_libiberty=NONE])

AC_ARG_WITH([bfd-include-dir],
  [  --with-bfd-include-dir=DIR
                          path to directory containing bfd.h],
  [ac_bfd_include_dir=$withval],
  [ac_bfd_include_dir=NONE])

AC_PROG_CC

if test "$ac_libiberty" = "NONE"; then
  AC_CHECK_LIB([iberty], [objalloc_create])
else
  LIBS="$ac_libiberty $LIBS"
fi
if test "$ac_libbfd" = "NONE"; then
  ac_libbfd=auto
  AC_CHECK_LIB([bfd], [bfd_openr], , [ac_libbfd=NONE])
else
  LIBS="$ac_libbfd $LIBS"
fi

if test "$ac_bfd_include_dir" != "NONE"; then
  CPPFLAGS="$CPPFLAGS -I$ac_bfd_include_dir"
fi

AC_CHECK_HEADERS([bfd.h], , [BFD_H="no"])

AC_CHECK_MEMBER([struct bfd_hash_table.entsize],
  [CPPFLAGS="$CPPFLAGS -DBFD_HASH_TABLE_HAS_ENTSIZE"],
  [],
  [[#include <bfd.h>]])

if ! test -e "objmanip-static"; then
  if test "$ac_libbfd" = "NONE"; then
    echo
    echo "Ksplice could not locate libbfd.a and/or libiberty.a on your system."
    echo "You can obtain these libraries from the GNU binutils collection."
    echo "These libraries are available on many Linux distributions as a"
    echo "package called 'binutils-dev' or 'binutils-devel'."
    echo "If your distribution does not provide GNU binutils, you can install"
    echo "GNU binutils from source -- see http://www.gnu.org/software/binutils/."
    echo
    echo "If these libraries are already installed on your system, then you need"
    echo "to tell Ksplice where to find them by running configure again:"
    echo
    echo "  ./configure --with-libbfd=<libbfd.a> --with-libiberty=<libiberty.a>"
    echo
    exit 1
  fi

  if test "$BFD_H" = "no"; then
    echo
    echo "Ksplice could not locate bfd.h on your system."
    echo "If this header file is already installed on your system, then you need"
    echo "to tell Ksplice where to find it by running configure again:"
    echo
    echo "  ./configure --with-bfd-include-dir=<directory-containing-bfd.h>"
    echo
    exit 1
  fi
fi

AC_PATH_PROG([PATCH], [patch])
AC_PATH_PROG([POD2MAN], [pod2man])
if test "$PATCH" = ""; then
  echo
  echo "Ksplice could not locate patch on your system."
  echo
  exit 1
fi
if test "$POD2MAN" = ""; then
  echo
  echo "Ksplice could not locate pod2man on your system."
  echo
  exit 1
fi

AC_PROG_PERL_MODULES([Cwd Getopt::Long File::Basename File::Copy File::Path File::Spec::Functions File::Temp Fatal IPC::Open2 IPC::Open3 Pod::Usage Text::ParseWords], ,
  [AC_MSG_ERROR([Missing some required perl modules])])

AC_CONFIG_FILES([Makefile kmodsrc/Makefile])
AC_OUTPUT
