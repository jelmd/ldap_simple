dnl Process this file with autoconf to produce a configure script.
dnl
AC_INIT([linux ldap_simple],[2.7.1],[jel+nfs@cs.ovgu.de],[ldap_simple])
AC_CANONICAL_BUILD([])
AC_CANONICAL_HOST([])
AC_CONFIG_MACRO_DIR(aclocal)
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE
AC_PREREQ(2.59)
AC_PREFIX_DEFAULT(/usr)
AM_MAINTAINER_MODE
AC_USE_SYSTEM_EXTENSIONS

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

# Cheocks for programs.
AC_CHECK_TOOL(AR, ar)

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET
LT_INIT
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG

CC_FOR_BUILD=${CC_FOR_BUILD-${CC-gcc}}
AC_SUBST(CC_FOR_BUILD)

# We need conffile.o xlog.o from libnfsidmap.a
XMSG='libnfsidmap.a not found. Package libnfsidmap-dev not installed?'
PKG_CHECK_VAR([NFSLIBDIR],[libnfsidmap],[libdir],
	[test -f ${NFSLIBDIR}/libnfsidmap.a || AC_MSG_ERROR([${XMSG}])],
	[AC_MSG_ERROR([${XMSG}])]
)

AC_CHECK_HEADER([ldap.h], [AC_CHECK_LIB([ldap], [ldap_initialize],
	[have_ldap="yes"],[have_ldap="no"])], [have_ldap="no"])
if test "x$have_ldap" = "xyes" ; then
	dnl check for sasl funcs
	AC_CHECK_HEADERS(sasl.h sasl/sasl.h)
	AC_CHECK_TYPE(sasl_interact_t,[have_sasl_interact_t="yes"],,[
		#ifdef HAVE_SASL_SASL_H
		#include <sasl/sasl.h>
		#elif defined(HAVE_SASL_H)
		#include <sasl.h>
		#endif])
	AC_CHECK_LIB([ldap],[ldap_sasl_interactive_bind_s],
		[have_ldap_sasl_interactive_bind_s="yes"])
	if test "x$have_sasl_interact_t" = "xyes" -a  \
		"x$have_ldap_sasl_interactive_bind_s" = "xyes" ; then
		AC_DEFINE([HAVE_LDAP_SASL_INTERACTIVE_BIND_S],[1],
			[Has ldap_sasl_interactive_bind_s function])
		AC_DEFINE([ENABLE_LDAP_SASL],1,[Enable LDAP SASL support])
			have_ldap_sasl="yes"
		AC_DEFINE([ENABLE_LDAP], 1, [Enable LDAP Support])
		have_ldap_sasl="yes"
	fi
	AC_DEFINE([ENABLE_LDAP], 1, [Enable LDAP Support])
elif test "x$enable_ldap$have_ldap" = "xyesno" ; then
	AC_MSG_ERROR(LDAP support not found!)
fi

AM_CONDITIONAL(ENABLE_LDAP, test "x$have_ldap" = "xyes")
AM_CONDITIONAL(ENABLE_LDAP_SASL, test "x$have_ldap_sasl" = "xyes")

dnl Where do the Plugins live
AC_ARG_WITH(pluginpath, [AS_HELP_STRING([--with-pluginpath=/foo],
	[Install the plugin in /foo/ instead of /usr/lib/libnfsidmap/. ])],
	path_plugins=$withval,
	path_plugins=""
)
if test -n "$path_plugins" ; then
	AC_DEFINE_UNQUOTED(PATH_PLUGINS, "$path_plugins",
		[Define this to change the plugins path])
fi
AM_CONDITIONAL(PATH_PLUGINS, test -n "$path_plugins")
AC_SUBST(PATH_PLUGINS, "$path_plugins")

AC_SUBST(AM_CPPFLAGS, "$AM_CPPFLAGS")

AC_SUBST(CFLAGS)
AC_SUBST(CXXFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

AC_SUBST(CFLAGS_FOR_BUILD)
AC_SUBST(CXXFLAGS_FOR_BUILD)
AC_SUBST(CPPFLAGS_FOR_BUILD)
AC_SUBST(LDFLAGS_FOR_BUILD)

my_am_cflags="\
 -pipe \
 -Wall \
 -Wextra \
 -Werror=missing-prototypes \
 -Werror=missing-declarations \
 -Werror=format=2 \
 -Werror=undef \
 -Werror=missing-include-dirs \
 -Werror=strict-aliasing=2 \
 -Werror=init-self \
 -Werror=implicit-function-declaration \
 -Werror=return-type \
 -Werror=switch \
 -Werror=overflow \
 -Werror=parentheses \
 -Werror=aggregate-return \
 -Werror=unused-result \
 -fno-strict-aliasing \
"

AC_DEFUN([CHECK_CCSUPPORT], [
  my_save_cflags="$CFLAGS"
  CFLAGS="-Werror $1"
  AC_MSG_CHECKING([whether CC supports $1])
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
    [AC_MSG_RESULT([yes])]
    [$2+=$1],
    [AC_MSG_RESULT([no])]
  )
  CFLAGS="$my_save_cflags"
])

CHECK_CCSUPPORT([-Werror=format-overflow=2], [flg1])
CHECK_CCSUPPORT([-Werror=int-conversion], [flg2])
CHECK_CCSUPPORT([-Werror=incompatible-pointer-types], [flg3])
CHECK_CCSUPPORT([-Werror=misleading-indentation], [flg4])
CHECK_CCSUPPORT([-Wno-cast-function-type], [flg5])

AC_SUBST([AM_CFLAGS], ["$my_am_cflags $flg1 $flg2 $flg3 $flg4 $flg5"])

# Make sure that $ACLOCAL_FLAGS are used during a rebuild
AC_SUBST([ACLOCAL_AMFLAGS], ["-I $ac_macro_dir \$(ACLOCAL_FLAGS)"])

AC_CONFIG_FILES([
    Makefile
])
AC_OUTPUT
