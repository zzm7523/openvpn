#!/bin/sh

#linux release configure
export CC=gcc
export CFLAGS="-O2 -pie -fPIE"
export CPPFLAGS=
export LDFLAGS="-ldl"

export IFCONFIG=/sbin/ifconfig
export IPROUTE=/sbin/ip
export ROUTE=/sbin/route

export DESPICABLE_ME=/home/despicable_me/trunk

# 使用动态库发布时最好链接系统自带的动态库, 因为*so文件的后缀可能不一样, 例如: fedora 18
# 系统自带的openssl库名是 libssl.so.10, libcrypto.so.10
# 通过官方openssl源码编译出来的库名是libcrypto.so.1.0.0, libssl.so.1.0.0

# 使用系统自带的openssl
unset OPENSSL_HOME
unset OPENSSL_CRYPTO_CFLAGS
unset OPENSSL_SSL_CFLAGS
unset OPENSSL_CRYPTO_LIBS
unset OPENSSL_SSL_LIBS

#export OPENSSL_HOME=${DESPICABLE_ME}/openssl-1.0.1m
#export OPENSSL_CRYPTO_CFLAGS=-I${OPENSSL_HOME}/include
#export OPENSSL_SSL_CFLAGS=-I${OPENSSL_HOME}/include
#export OPENSSL_CRYPTO_LIBS=${OPENSSL_HOME}/libcrypto.so
#export OPENSSL_SSL_LIBS=${OPENSSL_HOME}/libssl.so

# 使用系统自带的lzo
unset LZO_CFLAGS
unset LZO_LIBS

#export LZO_CFLAGS=-I${DESPICABLE_ME}/lzo-2.04/include
#export LZO_LIBS=${DESPICABLE_ME}/lzo-2.04/src/.libs/liblzo2.so

# 使用系统自带pkcs11-helper
unset PKCS11_HELPER_CFLAGS
unset PKCS11_HELPER_LIBS

#export PKCS11_HELPER_CFLAGS=-I${DESPICABLE_ME}/pkcs11-helper-1.11/include
#export PKCS11_HELPER_LIBS=${DESPICABLE_ME}/pkcs11-helper-1.11/lib/.libs/libpkcs11-helper.so

#export PKG_CONFIG_LIBDIR=${OPENSSL_HOME}:${DESPICABLE_ME}/pkcs11-helper-1.11/lib:/usr/lib/i386-linux-gnu/pkgconfig

# 使用缺省pkg-config lib dir
unset PKG_CONFIG_LIBDIR

#compile openvpn
cd ${DESPICABLE_ME}/openvpn
chmod +x configure
./configure --enable-iproute2 --enable-systemd --enable-x509-alt-username --enable-pkcs11 --disable-dependency-tracking --prefix=/usr --with-plugindir='${prefix}/lib/openvpn'
make clean
make

if test ! -d "${DESPICABLE_ME}/openvpn/release"; then
	mkdir ${DESPICABLE_ME}/openvpn/release
fi

#export dpkg template
cd ${DESPICABLE_ME}/openvpn/release
rm -rf i386
svn export https://10.5.12.12:2443/svn/despicable_me/trunk/openvpn/distro/dpkg/i386

#update DEBIAN/control
#...

cd ${DESPICABLE_ME}/openvpn/release/i386
\cp -f ${DESPICABLE_ME}/openvpn/src/openvpn/openvpn ./usr/sbin/openvpn
\cp -f ${DESPICABLE_ME}/openvpn/src/plugins/auth-pam/.libs/openvpn-plugin-auth-pam.so ./usr/lib/openvpn/openvpn-plugin-auth-pam.so
\cp -f ${DESPICABLE_ME}/openvpn/src/plugins/down-root/.libs/openvpn-plugin-down-root.so ./usr/lib/openvpn/openvpn-plugin-down-root.so

md5sum `find lib usr -type f` > DEBIAN/md5sums

cd ${DESPICABLE_ME}/openvpn/release
dpkg -b i386/ openvpn_6.1.4-1+deb8u1_i386.deb

