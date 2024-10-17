# ldap_simple
A simple efficient nfsidmap plugin to lookup the numerical ID of user and group names and vice versa via LDAP.

It is based on the **umich_ldap** plugin shipped with the [nfs-utils](https://git.linux-nfs.org/?p=steved/nfs-utils.git;a=tree;f=support/nfsidmap) for Linux. 


## Build
- ./autogen.sh
- ./configure --disable-silent-rules --disable-static
- make
- make install [DESTDIR=/tmp/root]

## Cleanup
- make {clean,distclean} OR
- ./autogen.sh clean

## Usage
See **ldap_simple**(5) man page.
