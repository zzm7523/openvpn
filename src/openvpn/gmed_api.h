#ifndef __GMED_API_H__
#define __GMED_API_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ENABLE_GUOMI
int SSL_CTX_use_GmedCertAPI_certificate (SSL_CTX *ssl_ctx, const char *path_name);
int GmedCertAPI_client_cert_cb (SSL *ssl, const char *path_name, X509 **sign_cert, EVP_PKEY **sign_key,
		X509 **encrypt_cert, EVP_PKEY **encrypt_key);
#endif

#ifdef __cplusplus
}
#endif

#endif /* !__GMED_API_H__ */
