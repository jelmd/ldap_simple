# ldap_simple
A simple efficient nfsidmap plugin to lookup the numerical ID of user and group names and vice versa via LDAP.

It is based on the **umich_ldap** plugin shipped with the [nfs-utils](https://git.linux-nfs.org/?p=steved/nfs-utils.git;a=tree;f=support/nfsidmap) for Linux. 

## Build Requirements
The following Ubuntu Packages are required to build the plugin by yourself:
- C compiler + tools (gcc, cpp/m4, make)
- Autotools (automake, autoconf, libtool)
- pkg-config (AC_MSG_ERR, pkg-config)
- libc6-dev
- libnfsidmap-dev (libnfsidmap.a, nfsidmap.h, nfsidmap_plugin.h)
- libldap-dev (ldap.h, libldap.so)
- libsasl2-dev (optional for ldap/sasl support).

Other distributions probably have packages with the same or a similar name.


## Build
- ./autogen.sh
- ./configure --disable-silent-rules --disable-static
- make
- make install [DESTDIR=/tmp/root]

## Cleanup
- make {clean,distclean} OR
- ./autogen.sh clean

## Runtime requirements
The following Ubuntu Packages are required to build the plugin by yourself:
- nfs-common
- libnfsidmap1
- libldap
- libsasl2 (if compiled with sasl2 support).

Other distributions probably have packages with the same or a similar name.

## Usage
See **ldap_simple**(5) man page.
