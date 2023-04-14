#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "basic.h"
#include "error.h"
#include "misc.h"
#include "console.h"
#include "crypto_openssl.h"
#include "ssl_common.h"
#include "ssl_verify_openssl.h"
#include "ssl_verify_backend.h"
#include "gmed_api.h"

#include <assert.h>

#ifdef ENABLE_GUOMI
#include <openssl/sm.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/encrypt_device.h>

#include "memdbg.h"

static int verify_pin_ENCRYPT_DEVICE_CONTAINER (ENCRYPT_DEVICE_CONTAINER *container, int *retry_count)
{
	int verify_ok = 0, passwd_len = USER_PASS_LEN, input_count = 0;
	struct gc_arena gc = gc_new ();
	char passwd[USER_PASS_LEN];
	struct buffer pass_prompt = alloc_buf_gc (128, &gc);

	buf_printf (&pass_prompt, "Enter Private Key Password:");

	/* 校验PIN后才能对私钥进行访问 */

	do 
	{
		if (!get_console_input (BSTR (&pass_prompt), false, passwd, USER_PASS_LEN))
		{
			msg (M_FATAL, "ERROR: could not read Private Key Password from stdin");
			break;
		}

		if (!(verify_ok = ENCRYPT_DEVICE_CONTAINER_verify_pin (container, 0, passwd, retry_count)))			
			crypto_msg (M_WARN, "ERROR: Private Key Password verify fail, retry_count=%d", *retry_count);
		/* 通知客户端重新输入私钥保护密码 */
		memset (passwd, 0x0, USER_PASS_LEN);

	} while (!verify_ok && retry_count > 0 && ++input_count < MAX_PRI_KEY_PASS_INPUT_COUNT);

	gc_free (&gc);
	return verify_ok;
}

int SSL_CTX_use_GmedCertAPI_certificate (SSL_CTX *ssl_ctx, const char *path_name)
{
	ENCRYPT_DEVICE_PROVIDER *provider = NULL;
	ENCRYPT_DEVICE *device = NULL;
	ENCRYPT_DEVICE_CONTAINER *container = NULL;
	EVP_PKEY *sign_key = NULL, *encrypt_key = NULL;
	X509 *sign_cert = NULL, *encrypt_cert = NULL;
	char *device_name = NULL;
	int retry_count = 10;

#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());	/* 只有主线程能调用 openvpn_exit () */
#endif

	if (!(provider = ENCRYPT_DEVICE_PROVIDER_get ()))
		crypto_msg (M_FATAL, "FATAL: Encrypt device provider not loaded!");

	if (!ENCRYPT_DEVICE_PROVIDER_parse_path (provider, path_name, &device_name, NULL, NULL))
		crypto_msg (M_FATAL, "FATAL: Encrypt device provider parse path fail, path=%s", path_name);

	device = ENCRYPT_DEVICE_acquire (provider, device_name, NULL);
	if (!device)
		crypto_msg (M_FATAL, "FATAL: Encrypt device acquire fail, name=%s", device_name);

	container = ENCRYPT_DEVICE_CONTAINER_open (device, path_name);
	if (!container)
		crypto_msg (M_FATAL, "FATAL: Encrypt device container open fail, path=%s", path_name);

	if (!ENCRYPT_DEVICE_CONTAINER_read_certs (container, &sign_cert, &sign_key, &encrypt_cert, &encrypt_key))
	{
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_ASN1_LIB);
		crypto_msg (M_FATAL, "TLS read certs fail, from encrypt device path=%s", path_name);
	}

	/* 加密证书没有单独指定或不存在时, 使用签名证书 */
	if (!encrypt_cert)
		encrypt_cert = X509_dup (sign_cert);

	if (!encrypt_key)
		encrypt_key = evp_pkey_dup (sign_key);

	/* 校验PIN后才能对私钥进行访问 */
	if (!verify_pin_ENCRYPT_DEVICE_CONTAINER (container, &retry_count))
		crypto_msg (M_FATAL, "FATAL: could not open Private Key fail, retry_count=%d", retry_count);

	/* cert->cert_info->key->pkey is NULL until we call SSL_CTX_use_certificate(), so we do it here then...  */
	if (!SSL_CTX_use_certificate (ssl_ctx, sign_cert))
		goto err;

	if (!SSL_CTX_use_PrivateKey (ssl_ctx, sign_key))
		goto err;

	if (encrypt_cert && !SSL_CTX_use_encrypt_certificate (ssl_ctx, encrypt_cert))
		goto err;

	if (encrypt_key && !SSL_CTX_use_encrypt_PrivateKey (ssl_ctx, encrypt_key))
		goto err;

	/* SSL_CTX_use_PrivateKey() increased the reference count in 'rsa', so
	 * we decrease it here with EVP_PKEY_free(), or it will never be cleaned up. */
	if (sign_key)
		EVP_PKEY_free (sign_key);
	if (encrypt_key)
		EVP_PKEY_free (encrypt_key);

	ENCRYPT_DEVICE_CONTAINER_dec_ref (container);
	if (device_name)
		OPENSSL_free (device_name);
	if (device)
		ENCRYPT_DEVICE_release (device);

	return 1;

err:
	if (container)
		ENCRYPT_DEVICE_CONTAINER_close (container);
	if (device_name)
		OPENSSL_free (device_name);
	if (device)
		ENCRYPT_DEVICE_release (device);
	if (sign_cert)
		X509_free (sign_cert);
	if (encrypt_cert)
		X509_free (encrypt_cert);
	if (sign_key)
		EVP_PKEY_free (sign_key);
	if (encrypt_key)
		EVP_PKEY_free (encrypt_key);
	return 0;
}

int GmedCertAPI_client_cert_cb (SSL *ssl, const char *path_name, X509 **sign_cert, EVP_PKEY **sign_key, X509 **encrypt_cert,
		EVP_PKEY **encrypt_key)
{
	ENCRYPT_DEVICE_PROVIDER *provider = NULL;
	ENCRYPT_DEVICE *device = NULL;
	ENCRYPT_DEVICE_CONTAINER *container = NULL;
	char *device_name = NULL;
	int retry_count = 10;

#ifdef THREAD_ACCESS_CHECK
	ASSERT (is_main_thread ());	/* 只有主线程能调用 openvpn_exit () */
#endif

	*sign_cert = NULL;
	*sign_key = NULL;
	*encrypt_cert = NULL;
	*encrypt_key = NULL;

	if (!(provider = ENCRYPT_DEVICE_PROVIDER_get ()))
	{
		crypto_msg (M_WARN, "FATAL: Encrypt device provider not loaded!");
		goto err;
	}

	if (!ENCRYPT_DEVICE_PROVIDER_parse_path (provider, path_name, &device_name, NULL, NULL))
	{
		crypto_msg (M_WARN, "FATAL: Encrypt device provider parse path fail, path=%s", path_name);
		goto err;
	}

	device = ENCRYPT_DEVICE_acquire (provider, device_name, NULL);
	if (!device)
	{
		crypto_msg (M_WARN, "FATAL: Encrypt device acquire fail, name=%s", device_name);
		goto err;
	}

	container = ENCRYPT_DEVICE_CONTAINER_open (device, path_name);
	if (!container)
	{
		crypto_msg (M_WARN, "FATAL: Encrypt device container open fail, path=%s", path_name);
		goto err;
	}

	if (!ENCRYPT_DEVICE_CONTAINER_read_certs (container, sign_cert, sign_key, encrypt_cert, encrypt_key))
	{
		SSLerr (SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_ASN1_LIB);
		crypto_msg (M_WARN, "TLS read certs fail, from encrypt device path=%s", path_name);
		goto err;
	}

	/* 加密证书没有单独指定或不存在时, 使用签名证书 */
	if (!(*encrypt_cert))
		*encrypt_cert = X509_dup (*sign_cert);
	if (!(*encrypt_key))
		*encrypt_key = evp_pkey_dup (*sign_key);

	/* 校验PIN后才能对私钥进行访问 */
	verify_pin_ENCRYPT_DEVICE_CONTAINER (container, &retry_count);

	ENCRYPT_DEVICE_CONTAINER_dec_ref(container);
	if (device_name)
		OPENSSL_free (device_name);
	if (device)
		ENCRYPT_DEVICE_release (device);

	return 1;

err:
	if (container)
		ENCRYPT_DEVICE_CONTAINER_close (container);
	if (device_name)
		OPENSSL_free (device_name);
	if (device)
		ENCRYPT_DEVICE_release (device);
	if (*sign_cert)
		X509_free (*sign_cert);
	if (*encrypt_cert)
		X509_free (*encrypt_cert);
	if (*sign_key)
		EVP_PKEY_free (*sign_key);
	if (*encrypt_key)
		EVP_PKEY_free (*encrypt_key);
	return 0;
}
#endif
