#ifndef _CRYPTOAPI_H_
#define _CRYPTOAPI_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
int SSL_CTX_use_CryptoAPI_certificate (SSL_CTX *ssl_ctx, const char *cert_prop);
int CryptoAPI_client_cert_cb (SSL *ssl, const char *cert_prop, X509 **x509, EVP_PKEY **pkey);
#endif

#ifdef __cplusplus
}
#endif

#endif /* !_CRYPTOAPI_H_ */
