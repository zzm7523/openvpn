#!/bin/sh

DESPICABLE_ME=/home/despicable_me/trunk

# 使用rpmbuild缺省设置
unset CC
unset CFLAGS
unset CPPFLAGS
unset LDFLAGS

# 使用系统缺省值
unset IFCONFIG
unset IPROUTE
unset ROUTE
 
# 使用系统自带的openssl
unset OPENSSL_HOME
unset OPENSSL_CRYPTO_CFLAGS
unset OPENSSL_SSL_CFLAGS
unset OPENSSL_CRYPTO_LIBS
unset OPENSSL_SSL_LIBS

# 使用系统自带的lzo
unset LZO_CFLAGS
unset LZO_LIBS

# 使用系统自带pkcs11-helper
unset PKCS11_HELPER_CFLAGS
unset PKCS11_HELPER_LIBS

# 使用缺省pkg-config lib dir
unset PKG_CONFIG_LIBDIR

# 确保configure可执行
chmod +x ${DESPICABLE_ME}/openvpn/configure

cd ${DESPICABLE_ME}/openvpn
# 必须清理, rpmbuild -ta 不会主动清理
make clean
if test -d build/debug; then
rm -rf build/debug
fi
if test -d build/release; then
rm -rf build/release
fi

cd /root
if test -d openvpn-6.1.4; then
rm -rf openvpn-6.1.4
fi

if test -e openvpn-6.1.4.tar.gz; then
rm openvpn-6.1.4.tar.gz
fi

ln -s ${DESPICABLE_ME}/openvpn openvpn-6.1.4
tar czvhf openvpn-6.1.4.tar.gz openvpn-6.1.4/

rpmbuild -tb openvpn-6.1.4.tar.gz
