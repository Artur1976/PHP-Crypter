#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

#define AES_KEY_LEN 32
#define AES_IV_LEN 16

// --- Szablony dla plikÃ³w ÅºrÃ³dÅ‚owych ---

const char* config_m4_template =
    "PHP_ARG_ENABLE([ext_name], whether to enable [ext_name] support,\n"
    "[  --enable-[ext_name]        Enable [ext_name] support])\n"
    "\n"
    "if test \"$PHP_[EXT_NAME]\" != \"no\"; then\n"
    "    PHP_NEW_EXTENSION([ext_name], [ext_name].c, $ext_shared)\n"
    "fi\n";

const char* config_w32_template =
    "ARG_ENABLE(\"[ext_name]\", \"enable [ext_name] support\", \"no\");\n"
    "\n"
    "if (PHP_[EXT_NAME] != \"no\") {\n"
    "    EXTENSION(\"[ext_name]\", \"[ext_name].c\");\n"
    "}\n";

// --- ZAKTUALIZOWANY SZABLON .h ZGODNIE Z PROÅšBÄ„ ---
const char* ext_header_template =
    "#ifndef PHP_[EXT_NAME]_H\n"
    "#define PHP_[EXT_NAME]_H\n"
    "\n"
    "extern zend_module_entry [ext_name]_module_entry;\n"
    "#define phpext_[ext_name]_ptr &[ext_name]_module_entry\n"
    "\n"
    "#define [EXT_NAME]_VERSION \"0.1.1\"\n"
    "#define [EXT_NAME]_SIG \"<?php // @[ext_name]\"\n"
    "\n"
    "#define [EXT_NAME]_CIPHER_ALGO \"AES-256-CBC\"\n"
    "#define [EXT_NAME]_KEY_LENGTH 32\n"
    "\n"
    "ZEND_BEGIN_MODULE_GLOBALS([ext_name])\n"
    "    zend_bool decrypt;\n"
    "ZEND_END_MODULE_GLOBALS([ext_name])\n"
    "\n"
    "#define [EXT_NAME]_G(v) ([ext_name]_globals.v)\n"
    "\n"
    "#endif\n";

// --- ZAKTUALIZOWANY SZABLON .c ZGODNIE Z PROÅšBÄ„ ---
const char* ext_c_template =
    "#include \"php.h\"\n"
    "#include \"ext/standard/info.h\"\n"
    "#include \"ext/standard/file.h\"\n"
    "#include \"ext/standard/base64.h\"\n"
    "#include \"ext/openssl/php_openssl.h\"\n"
    "#include \"[ext_name].h\"\n"
    "\n"
    "ZEND_DECLARE_MODULE_GLOBALS([ext_name])\n"
    "\n"
    "static zend_op_array* (*old_compile_file)(zend_file_handle *file_handle, int type);\n"
    "static zend_op_array* new_compile_file(zend_file_handle *file_handle, int type)\n"
    "{\n"
    "    if (PHP_VERSION_ID < 80200 || ! [EXT_NAME]_G(decrypt)) {\n"
    "        return old_compile_file(file_handle, type);\n"
    "    }\n"
    "\n"
    "    // @char\n"
    "\n"
    "    do {\n"
    "        FILE *fp;\n"
    "\n"
    "        fp = fopen(ZSTR_VAL(file_handle->filename), \"rb\");\n"
    "\n"
    "        if (! fp) {\n"
    "            break;\n"
    "        }\n"
    "\n"
    "        char sig[] = [EXT_NAME]_SIG;\n"
    "        size_t sig_length = strlen(sig);\n"
    "\n"
    "        char *sig_buffer = (char *)emalloc(sig_length);\n"
    "        fread(sig_buffer, sizeof(char), sig_length, fp);\n"
    "\n"
    "        if (memcmp(sig_buffer, sig, sig_length) != 0) {\n"
    "            fclose(fp);\n"
    "\n"
    "            efree(sig_buffer);\n"
    "\n"
    "            break;\n"
    "        }\n"
    "\n"
    "        efree(sig_buffer);\n"
    "\n"
    "        fseek(fp, 0, SEEK_END);\n"
    "        long file_size = ftell(fp);\n"
    "        fseek(fp, 0, SEEK_SET);\n"
    "\n"
    "        char *file_contents = (char *)emalloc(file_size);\n"
    "        fread(file_contents, sizeof(char), file_size, fp);\n"
    "\n"
    "        fclose(fp);\n"
    "\n"
    "        strtok(file_contents, \"#\");\n"
    "        char *encoded_data = strtok(NULL, \"#\");\n"
    "\n"
    "        efree(file_contents);\n"
    "\n"
    "        if (! encoded_data) {\n"
    "            break;\n"
    "        }\n"
    "\n"
    "        zend_string *tmp_encoded_data = zend_string_init(encoded_data, strlen(encoded_data), 0);\n"
    "        zend_string *decoded_data = php_base64_decode_str(tmp_encoded_data);\n"
    "        zend_string_release(tmp_encoded_data);\n"
    "\n"
    "        if (! ZSTR_LEN(decoded_data)) {\n"
    "            break;\n"
    "        }\n"
    "\n"
    "        char *[ext_name]_version = strtok(ZSTR_VAL(decoded_data), \",\");\n"
    "        char *encoded_iv = strtok(NULL, \",\");\n"
    "        char *encrypted_data = strtok(NULL, \",\");\n"
    "\n"
    "        zend_string_release(decoded_data);\n"
    "\n"
    "        if (! [ext_name]_version || ! encoded_iv || ! encrypted_data) {\n"
    "            break;\n"
    "        }\n"
    "\n"
    "        if (strcmp([ext_name]_version, [EXT_NAME]_VERSION) != 0) {\n"
    "            break;\n"
    "        }\n"
    "\n"
    "        zend_string *tmp_encoded_iv = zend_string_init(encoded_iv, strlen(encoded_iv), 0);\n"
    "        zend_string *decoded_iv = php_base64_decode_str(tmp_encoded_iv);\n"
    "        zend_string_release(tmp_encoded_iv);\n"
    "\n"
    "        if (! ZSTR_LEN(decoded_iv)) {\n"
    "            break;\n"
    "        }\n"
    "\n"
    "        char *iv = ZSTR_VAL(decoded_iv);\n"
    "\n"
    "        size_t key_xor_length = [EXT_NAME]_KEY_LENGTH;\n"
    "        size_t xor_key_length = [EXT_NAME]_KEY_LENGTH;\n"
    "\n"
    "        char key_xor[key_xor_length];\n"
    "        char xor_key[xor_key_length];\n"
    "\n"
    "        // @memcpy\n"
    "\n"
    "        char key[key_xor_length];\n"
    "\n"
    "        for (size_t i = 0; i < key_xor_length; i++) {\n"
    "            key[i] = key_xor[i] ^ xor_key[i % sizeof(xor_key)];\n"
    "        }\n"
    "\n"
    "        char *cipher_algo = [EXT_NAME]_CIPHER_ALGO;\n"
    "\n"
    "        zend_string *decrypted_data = php_openssl_decrypt(\n"
    "            encrypted_data, strlen(encrypted_data),\n"
    "            cipher_algo, strlen(cipher_algo),\n"
    "            key, strlen(key),\n"
    "            0,\n"
    "            iv, strlen(iv),\n"
    "            NULL, 0,\n"
    "            NULL, 0\n"
    "        );\n"
    "\n"
    "        if (! ZSTR_LEN(decrypted_data)) {\n"
    "            break;\n"
    "        }\n"
    "\n"
    "        size_t decrypted_data_length = ZSTR_LEN(decrypted_data);\n"
    "        char *new_buffer = estrndup(ZSTR_VAL(decrypted_data), decrypted_data_length);\n"
    "\n"
    "        zend_string_release(decrypted_data);\n"
    "\n"
    "        char *tmp_buffer = NULL;\n"
    "        size_t tmp_length = 0;\n"
    "\n"
    "        if (zend_stream_fixup(file_handle, &tmp_buffer, &tmp_length) == FAILURE) {\n"
    "            break;\n"
    "        }\n"
    "\n"
    "        if (file_handle->buf != NULL) {\n"
    "            efree(file_handle->buf);\n"
    "        }\n"
    "\n"
    "        file_handle->buf = new_buffer;\n"
    "        file_handle->len = decrypted_data_length;\n"
    "    } while (0);\n"
    "\n"
    "    return old_compile_file(file_handle, type);\n"
    "}\n"
    "\n"
    "static void php_[ext_name]_init_globals(zend_[ext_name]_globals *[ext_name]_globals) {\n"
    "    [ext_name]_globals->decrypt = 1;\n"
    "}\n"
    "\n"
    "PHP_INI_BEGIN()\n"
    "    STD_PHP_INI_BOOLEAN(\"[ext_name].decrypt\", \"1\", PHP_INI_ALL, OnUpdateBool, decrypt, zend_[ext_name]_globals, [ext_name]_globals)\n"
    "PHP_INI_END()\n"
    "\n"
    "PHP_MINIT_FUNCTION([ext_name])\n"
    "{\n"
    "    ZEND_INIT_MODULE_GLOBALS([ext_name], php_[ext_name]_init_globals, NULL);\n"
    "    REGISTER_INI_ENTRIES();\n"
    "\n"
    "    old_compile_file = zend_compile_file;\n"
    "    zend_compile_file = new_compile_file;\n"
    "\n"
    "    return SUCCESS;\n"
    "}\n"
    "\n"
    "PHP_MSHUTDOWN_FUNCTION([ext_name])\n"
    "{\n"
    "    zend_compile_file = old_compile_file;\n"
    "\n"
    "    return SUCCESS;\n"
    "}\n"
    "\n"
    "PHP_RINIT_FUNCTION([ext_name])\n"
    "{\n"
    "    return SUCCESS;\n"
    "}\n"
    "\n"
    "PHP_RSHUTDOWN_FUNCTION([ext_name])\n"
    "{\n"
    "    return SUCCESS;\n"
    "}\n"
    "\n"
    "PHP_MINFO_FUNCTION([ext_name])\n"
    "{\n"
    "    php_info_print_table_start();\n"
    "    php_info_print_table_row(2, \"[ext_name]\", \"enabled\");\n"
    "    php_info_print_table_row(2, \"version\", [EXT_NAME]_VERSION);\n"
    "    php_info_print_table_end();\n"
    "}\n"
    "\n"
    "zend_function_entry [ext_name]_functions[] = {\n"
    "    ZEND_FE_END\n"
    "};\n"
    "\n"
    "zend_module_entry [ext_name]_module_entry = {\n"
    "    STANDARD_MODULE_HEADER,\n"
    "    \"[ext_name]\",\n"
    "    [ext_name]_functions,\n"
    "    PHP_MINIT([ext_name]),\n"
    "    PHP_MSHUTDOWN([ext_name]),\n"
    "    PHP_RINIT([ext_name]),\n"
    "    PHP_RSHUTDOWN([ext_name]),\n"
    "    PHP_MINFO([ext_name]),\n"
    "    [EXT_NAME]_VERSION,\n"
    "    STANDARD_MODULE_PROPERTIES\n"
    "};\n"
    "\n"
    "ZEND_GET_MODULE([ext_name])\n";

const char* php_openssl_h_template =
    "/*\n"
    "   +----------------------------------------------------------------------+\n"
    "   | Copyright (c) The PHP Group                                          |\n"
    "   +----------------------------------------------------------------------+\n"
    "   | This source file is subject to version 3.01 of the PHP license,      |\n"
    "   | that is bundled with this package in the file LICENSE, and is        |\n"
    "   | available through the world-wide-web at the following url:           |\n"
    "   | https://www.php.net/license/3_01.txt                                 |\n"
    "   | If you did not receive a copy of the PHP license and are unable to   |\n"
    "   | obtain it through the world-wide-web, please send a note to          |\n"
    "   | license@php.net so we can mail you a copy immediately.               |\n"
    "   +----------------------------------------------------------------------+\n"
    "   | Authors: Stig Venaas <venaas@php.net>                                |\n"
    "   |          Wez Furlong <wez@thebrainroom.com                           |\n"
    "   +----------------------------------------------------------------------+\n"
    " */\n"
    "\n"
    "#ifndef PHP_OPENSSL_H\n"
    "#define PHP_OPENSSL_H\n"
    "/* HAVE_OPENSSL would include SSL MySQL stuff */\n"
    "#ifdef HAVE_OPENSSL_EXT\n"
    "extern zend_module_entry openssl_module_entry;\n"
    "#define phpext_openssl_ptr &openssl_module_entry\n"
    "\n"
    "#include \"php_version.h\"\n"
    "#define PHP_OPENSSL_VERSION PHP_VERSION\n"
    "\n"
    "#include <openssl/opensslv.h>\n"
    "#if defined(LIBRESSL_VERSION_NUMBER)\n"
    "/* LibreSSL version check */\n"
    "#if LIBRESSL_VERSION_NUMBER < 0x20700000L\n"
    "#define PHP_OPENSSL_API_VERSION 0x10001\n"
    "#else\n"
    "#define PHP_OPENSSL_API_VERSION 0x10100\n"
    "#endif\n"
    "#else\n"
    "/* OpenSSL version check */\n"
    "#if OPENSSL_VERSION_NUMBER < 0x10100000L\n"
    "#define PHP_OPENSSL_API_VERSION 0x10002\n"
    "#elif OPENSSL_VERSION_NUMBER < 0x30000000L\n"
    "#define PHP_OPENSSL_API_VERSION 0x10100\n"
    "#else\n"
    "#define PHP_OPENSSL_API_VERSION 0x30000\n"
    "#endif\n"
    "#endif\n"
    "\n"
    "#define OPENSSL_RAW_DATA 1\n"
    "#define OPENSSL_ZERO_PADDING 2\n"
    "#define OPENSSL_DONT_ZERO_PAD_KEY 4\n"
    "\n"
    "#define OPENSSL_ERROR_X509_PRIVATE_KEY_VALUES_MISMATCH 0x0B080074\n"
    "\n"
    "/* Used for client-initiated handshake renegotiation DoS protection*/\n"
    "#define OPENSSL_DEFAULT_RENEG_LIMIT 2\n"
    "#define OPENSSL_DEFAULT_RENEG_WINDOW 300\n"
    "#define OPENSSL_DEFAULT_STREAM_VERIFY_DEPTH 9\n"
    "#define OPENSSL_DEFAULT_STREAM_CIPHERS \"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:\" \\\n"
    "	\"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:\" \\\n"
    "	\"DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:\" \\\n"
    "	\"ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:\" \\\n"
    "	\"ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:\" \\\n"
    "	\"DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:\" \\\n"
    "	\"AES256-GCM-SHA384:AES128:AES256:HIGH:!SSLv2:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!RC4:!ADH\"\n"
    "\n"
    "#include <openssl/err.h>\n"
    "\n"
    "#ifdef PHP_WIN32\n"
    "#	define PHP_OPENSSL_API __declspec(dllexport)\n"
    "#elif defined(__GNUC__) && __GNUC__ >= 4\n"
    "#	define PHP_OPENSSL_API __attribute__((visibility(\"default\")))\n"
    "#else\n"
    "#	define PHP_OPENSSL_API\n"
    "#endif\n"
    "\n"
    "struct php_openssl_errors {\n"
    "	int buffer[ERR_NUM_ERRORS];\n"
    "	int top;\n"
    "	int bottom;\n"
    "};\n"
    "\n"
    "ZEND_BEGIN_MODULE_GLOBALS(openssl)\n"
    "	struct php_openssl_errors *errors;\n"
    "ZEND_END_MODULE_GLOBALS(openssl)\n"
    "\n"
    "#define OPENSSL_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(openssl, v)\n"
    "\n"
    "#if defined(ZTS) && defined(COMPILE_DL_OPENSSL)\n"
    "ZEND_TSRMLS_CACHE_EXTERN();\n"
    "#endif\n"
    "\n"
    "php_stream_transport_factory_func php_openssl_ssl_socket_factory;\n"
    "\n"
    "void php_openssl_store_errors(void);\n"
    "\n"
    "/* openssl file path extra */\n"
    "bool php_openssl_check_path_ex(\n"
    "		const char *file_path, size_t file_path_len, char *real_path, uint32_t arg_num,\n"
    "		bool contains_file_protocol, bool is_from_array, const char *option_name);\n"
    "\n"
    "/* openssl file path check */\n"
    "static inline bool php_openssl_check_path(\n"
    "		const char *file_path, size_t file_path_len, char *real_path, uint32_t arg_num)\n"
    "{\n"
    "	return php_openssl_check_path_ex(\n"
    "			file_path, file_path_len, real_path, arg_num, false, false, NULL);\n"
    "}\n"
    "\n"
    "/* openssl file path extra check with zend string */\n"
    "static inline bool php_openssl_check_path_str_ex(\n"
    "		zend_string *file_path, char *real_path, uint32_t arg_num,\n"
    "		bool contains_file_protocol, bool is_from_array, const char *option_name)\n"
    "{\n"
    "	return php_openssl_check_path_ex(\n"
    "			ZSTR_VAL(file_path), ZSTR_LEN(file_path), real_path, arg_num, contains_file_protocol,\n"
    "			is_from_array, option_name);\n"
    "}\n"
    "\n"
    "/* openssl file path check with zend string */\n"
    "static inline bool php_openssl_check_path_str(\n"
    "		zend_string *file_path, char *real_path, uint32_t arg_num)\n"
    "{\n"
    "	return php_openssl_check_path_str_ex(file_path, real_path, arg_num, true, false, NULL);\n"
    "}\n"
    "\n"
    "PHP_OPENSSL_API zend_long php_openssl_cipher_iv_length(const char *method);\n"
    "PHP_OPENSSL_API zend_long php_openssl_cipher_key_length(const char *method);\n"
    "PHP_OPENSSL_API zend_string* php_openssl_random_pseudo_bytes(zend_long length);\n"
    "PHP_OPENSSL_API zend_string* php_openssl_encrypt(\n"
    "	const char *data, size_t data_len,\n"
    "	const char *method, size_t method_len,\n"
    "	const char *password, size_t password_len,\n"
    "	zend_long options,\n"
    "	const char *iv, size_t iv_len,\n"
    "	zval *tag, zend_long tag_len,\n"
    "	const char *aad, size_t aad_len);\n"
    "PHP_OPENSSL_API zend_string* php_openssl_decrypt(\n"
    "	const char *data, size_t data_len,\n"
    "	const char *method, size_t method_len,\n"
    "	const char *password, size_t password_len,\n"
    "	zend_long options,\n"
    "	const char *iv, size_t iv_len,\n"
    "	const char *tag, zend_long tag_len,\n"
    "	const char *aad, size_t aad_len);\n"
    "\n"
    "/* OpenSSLCertificate class */\n"
    "\n"
    "typedef struct _php_openssl_certificate_object {\n"
    "	X509 *x509;\n"
    "	zend_object std;\n"
    "} php_openssl_certificate_object;\n"
    "\n"
    "extern zend_class_entry *php_openssl_certificate_ce;\n"
    "\n"
    "static inline php_openssl_certificate_object *php_openssl_certificate_from_obj(zend_object *obj) {\n"
    "	return (php_openssl_certificate_object *)((char *)(obj) - XtOffsetOf(php_openssl_certificate_object, std));\n"
    "}\n"
    "\n"
    "#define Z_OPENSSL_CERTIFICATE_P(zv) php_openssl_certificate_from_obj(Z_OBJ_P(zv))\n"
    "\n"
    "PHP_MINIT_FUNCTION(openssl);\n"
    "PHP_MSHUTDOWN_FUNCTION(openssl);\n"
    "PHP_MINFO_FUNCTION(openssl);\n"
    "PHP_GINIT_FUNCTION(openssl);\n"
    "PHP_GSHUTDOWN_FUNCTION(openssl);\n"
    "\n"
    "#ifdef PHP_WIN32\n"
    "#define PHP_OPENSSL_BIO_MODE_R(flags) (((flags) & PKCS7_BINARY) ? \"rb\" : \"r\")\n"
    "#define PHP_OPENSSL_BIO_MODE_W(flags) (((flags) & PKCS7_BINARY) ? \"wb\" : \"w\")\n"
    "#else\n"
    "#define PHP_OPENSSL_BIO_MODE_R(flags) \"r\"\n"
    "#define PHP_OPENSSL_BIO_MODE_W(flags) \"w\"\n"
    "#endif\n"
    "\n"
    "#else\n"
    "\n"
    "#define phpext_openssl_ptr NULL\n"
    "\n"
    "#endif\n"
    "\n"
    "\n"
    "#endif\n";

// --- Funkcje pomocnicze do obsÅ‚ugi ciÄ…gÃ³w znakÃ³w i plikÃ³w ---

char* str_replace(const char* orig, const char* rep, const char* with) {
    char *result, *ins, *tmp;
    int len_rep, len_with, len_front, count;

    if (!orig || !rep) return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0) return NULL;
    if (!with) with = "";
    len_with = strlen(with);

    ins = (char*)orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);
    if (!result) return NULL;

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig);
    return result;
}

char* strupr(char* str) {
    char* p = str;
    while (*p) {
        *p = toupper((unsigned char)*p);
        p++;
    }
    return str;
}

int create_dir(const char* path) {
    #ifdef _WIN32
        return mkdir(path);
    #else
        return mkdir(path, 0777);
    #endif
}

// --- Funkcje kryptograficzne i pomocnicze (Base64, odczyt/zapis plikÃ³w) ---

char *base64_encode(const unsigned char *input, int length) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    char *buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    BIO_free_all(b64);
    return buff;
}

unsigned char *base64_decode(const char *input, int *out_len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf((void*)input, -1);
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    int decode_len = strlen(input) * 3 / 4;
    unsigned char *buffer = (unsigned char *)malloc(decode_len + 2);
    *out_len = BIO_read(b64, buffer, decode_len + 1);
    buffer[*out_len] = '\0';
    BIO_free_all(b64);
    return buffer;
}

unsigned char* encrypt_aes(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, const unsigned char* iv, int* ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    unsigned char *ciphertext = malloc(plaintext_len + AES_IV_LEN);

    if(!(ctx = EVP_CIPHER_CTX_new())) return NULL;
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return NULL;
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return NULL;
    *ciphertext_len = len;
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return NULL;
    *ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

unsigned char* decrypt_aes(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* key, const unsigned char* iv, int* plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    unsigned char *plaintext = malloc(ciphertext_len);

    if(!(ctx = EVP_CIPHER_CTX_new())) return NULL;
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return NULL;
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return NULL;
    *plaintext_len = len;
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return NULL;
    *plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

char* read_file(const char* filename, long* length) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        // Zmieniono, aby nie wypisywaÄ‡ bÅ‚Ä™du, gdy plik po prostu nie istnieje
        // perror("Error opening file");
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    *length = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* buffer = malloc(*length + 1);
    if (*length != fread(buffer, 1, *length, f)) {
        fclose(f);
        free(buffer);
        fprintf(stderr, "Error reading file\n");
        return NULL;
    }
    buffer[*length] = '\0';
    fclose(f);
    return buffer;
}

int write_file(const char* filename, const char* data, long length) {
    FILE* f = fopen(filename, "wb");
    if (!f) {
        perror("Error writing to file");
        return 0;
    }
    if (length != fwrite(data, 1, length, f)) {
        fclose(f);
        fprintf(stderr, "Error writing to file\n");
        return 0;
    }
    fclose(f);
    return 1;
}

// --- GÅ‚Ã³wne funkcje dla poleceÅ„ ---

void run_generate(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s generate <name> [optional_output_file]\n", argv[0]);
        return;
    }
    char* name = argv[2];
    char* optional_output_file = (argc > 3) ? argv[3] : NULL;

    // 1. Generowanie kluczy kryptograficznych
    unsigned char key[AES_KEY_LEN];
    unsigned char xor_key[AES_KEY_LEN];
    if (RAND_bytes(key, sizeof(key)) != 1 || RAND_bytes(xor_key, sizeof(xor_key)) != 1) {
        fprintf(stderr, "Error: Could not generate random keys.\n");
        return;
    }

    // 2. Tworzenie struktury katalogÃ³w
    char path_root[256];
    sprintf(path_root, ".crypter");
    create_dir(path_root);

    char path_ext[256];
    sprintf(path_ext, "%s/%s", path_root, name);
    if (create_dir(path_ext) != 0) {
        fprintf(stderr, "Error: Could not create directory %s. It might already exist.\n", path_ext);
        return;
    }
    printf("Created directory: %s\n", path_ext);

    // TwÃ³rz podkatalogi ext/openssl jeden po drugim
    char path_openssl[512];
    sprintf(path_openssl, "%s/ext", path_ext);
    create_dir(path_openssl); // UtwÃ³rz 'ext'

    strcat(path_openssl, "/openssl");
    if (create_dir(path_openssl) != 0) { // UtwÃ³rz 'openssl' wewnÄ…trz 'ext'
        fprintf(stderr, "Error: Could not create directory %s.\n", path_openssl);
        return;
    }

    // 3. Przygotowanie zaciemnionego kodu C dla kluczy (logika obfuskacji)
    char* char_declarations[128];
    char temp_buf[128];

    int indices[128];
    for(int i=0; i<128; i++) indices[i] = i;
    srand(time(NULL));
    for(int i=0; i<128; i++) {
        int j = rand() % 128;
        int temp = indices[i];
        indices[i] = indices[j];
        indices[j] = temp;
    }

    int char_idx = 0;
    for (int i = 0; i < AES_KEY_LEN; i++) {
        unsigned char key_xor_byte = key[i] ^ xor_key[i];
        sprintf(temp_buf, "unsigned char key_xor_%d[] = {0x%02x};", i + 1, key_xor_byte);
        char_declarations[char_idx++] = strdup(temp_buf);

        sprintf(temp_buf, "unsigned char xor_key_%d[] = {0x%02x};", i + 1, xor_key[i]);
        char_declarations[char_idx++] = strdup(temp_buf);
    }
    
    for (int i = 0; i < 32; i++) {
        unsigned char random_byte = 0;
        RAND_bytes(&random_byte, 1);
        sprintf(temp_buf, "unsigned char key_xor_%d[] = {0x%02x};", i + 33, random_byte);
        char_declarations[char_idx++] = strdup(temp_buf);

        RAND_bytes(&random_byte, 1);
        sprintf(temp_buf, "unsigned char xor_key_%d[] = {0x%02x};", i + 33, random_byte);
        char_declarations[char_idx++] = strdup(temp_buf);
    }

    char final_char_str[16384] = "";
    for(int i=0; i<128; i++) {
        strcat(final_char_str, char_declarations[indices[i]]);
        strcat(final_char_str, " ");
        free(char_declarations[indices[i]]);
    }

    char final_memcpy_str[8192] = "";
    for (int i = 0; i < AES_KEY_LEN; i++) {
        sprintf(temp_buf, "memcpy(key_xor + %d, key_xor_%d, sizeof(key_xor_%d)); ", i, i + 1, i + 1);
        strcat(final_memcpy_str, temp_buf);
    }
    for (int i = 0; i < AES_KEY_LEN; i++) {
        sprintf(temp_buf, "memcpy(xor_key + %d, xor_key_%d, sizeof(xor_key_%d)); ", i, i + 1, i + 1);
        strcat(final_memcpy_str, temp_buf);
    }


    // 4. Generowanie plikÃ³w z szablonÃ³w
    char name_upper[128];
    strcpy(name_upper, name);
    strupr(name_upper);

    char file_path[512];

    char* content_m4 = str_replace(config_m4_template, "[ext_name]", name);
    char* final_content_m4 = str_replace(content_m4, "[EXT_NAME]", name_upper);
    sprintf(file_path, "%s/config.m4", path_ext);
    write_file(file_path, final_content_m4, strlen(final_content_m4));
    printf("Created file: %s\n", file_path);
    free(content_m4); free(final_content_m4);

    char* content_w32 = str_replace(config_w32_template, "[ext_name]", name);
    char* final_content_w32 = str_replace(content_w32, "[EXT_NAME]", name_upper);
    sprintf(file_path, "%s/config.w32", path_ext);
    write_file(file_path, final_content_w32, strlen(final_content_w32));
    printf("Created file: %s\n", file_path);
    free(content_w32); free(final_content_w32);

    char* content_h = str_replace(ext_header_template, "[ext_name]", name);
    char* final_content_h = str_replace(content_h, "[EXT_NAME]", name_upper);
    sprintf(file_path, "%s/%s.h", path_ext, name);
    write_file(file_path, final_content_h, strlen(final_content_h));
    printf("Created file: %s\n", file_path);
    free(content_h); free(final_content_h);

    char* content_c1 = str_replace(ext_c_template, "[ext_name]", name);
    char* content_c2 = str_replace(content_c1, "[EXT_NAME]", name_upper);
    char* content_c3 = str_replace(content_c2, "// @char", final_char_str);
    char* final_content_c = str_replace(content_c3, "// @memcpy", final_memcpy_str);
    sprintf(file_path, "%s/%s.c", path_ext, name);
    write_file(file_path, final_content_c, strlen(final_content_c));
    printf("Created file: %s\n", file_path);
    free(content_c1); free(content_c2); free(content_c3); free(final_content_c);

    // Zapisz plik php_openssl.h
    sprintf(file_path, "%s/ext/openssl/php_openssl.h", path_ext);
    write_file(file_path, php_openssl_h_template, strlen(php_openssl_h_template));
    printf("Created file: %s\n", file_path);

    // 5. Tworzenie i zapisywanie Å‚adunku (payload)
    char* key_b64 = base64_encode(key, AES_KEY_LEN);
    char* xor_key_b64 = base64_encode(xor_key, AES_KEY_LEN);
    size_t payload_len = strlen(name) + 1 + strlen(key_b64) + 1 + strlen(xor_key_b64);
    char* payload = malloc(payload_len + 1);
    sprintf(payload, "%s,%s,%s", name, key_b64, xor_key_b64);
    char* final_payload_b64 = base64_encode((unsigned char*)payload, strlen(payload));

    // 6. Automatyczny zapis Å‚adunku do pliku .key
    char key_file_path[512];
    sprintf(key_file_path, "%s/%s.key", path_ext, name);
    if (write_file(key_file_path, final_payload_b64, strlen(final_payload_b64))) {
        printf("Payload saved to: %s\n", key_file_path);
    } else {
        fprintf(stderr, "Error: Could not save payload to file %s\n", key_file_path);
    }

    printf("\nDone!\n");
    printf("Payload: %s\n", final_payload_b64);

    // 7. Zapis do opcjonalnego pliku wyjÅ›ciowego (jeÅ›li podano)
    if (optional_output_file) {
        if (write_file(optional_output_file, final_payload_b64, strlen(final_payload_b64))) {
            printf("Payload also saved to: %s\n", optional_output_file);
        } else {
            fprintf(stderr, "Error: Could not save payload to file %s\n", optional_output_file);
        }
    }

    free(key_b64);
    free(xor_key_b64);
    free(payload);
    free(final_payload_b64);
}

void run_encrypt_decrypt(int argc, char *argv[]) {
    char* command = argv[1];
    char* id_or_payload = argv[2]; // MoÅ¼e to byÄ‡ nazwa aplikacji lub peÅ‚ny Å‚adunek
    char* filename = argv[3];
    char* payload_b64 = NULL;
    long payload_len_read;

    // SprawdÅº, czy drugi argument to nazwa aplikacji, prÃ³bujÄ…c odczytaÄ‡ plik .key
    char key_path[512];
    sprintf(key_path, ".crypter/%s/%s.key", id_or_payload, id_or_payload);
    
    payload_b64 = read_file(key_path, &payload_len_read);

    if (payload_b64 == NULL) {
        // JeÅ›li plik .key nie istnieje, potraktuj drugi argument jako peÅ‚ny Å‚adunek
        payload_b64 = id_or_payload;
    }

    int payload_len;
    unsigned char* payload = base64_decode(payload_b64, &payload_len);
    if (!payload) {
        fprintf(stderr, "Error: Invalid payload format or app name '%s' not found.\n", id_or_payload);
        if (payload_b64 != id_or_payload) free(payload_b64); // Uwolnij pamiÄ™Ä‡, jeÅ›li byÅ‚a alokowana przez read_file
        return;
    }

    char* name = strtok((char*)payload, ",");
    char* key_b64 = strtok(NULL, ",");
    
    if (!name || !key_b64) {
        fprintf(stderr, "Error: Invalid payload content.\n");
        free(payload);
        if (payload_b64 != id_or_payload) free(payload_b64);
        return;
    }

    int key_len;
    unsigned char* key = base64_decode(key_b64, &key_len);
    if (!key || key_len != AES_KEY_LEN) {
        fprintf(stderr, "Error: Invalid key in payload.\n");
        free(payload);
        if(key) free(key);
        if (payload_b64 != id_or_payload) free(payload_b64);
        return;
    }

    if (strcmp(command, "encrypt") == 0) {
        long file_len;
        char* file_contents = read_file(filename, &file_len);
        if (!file_contents) { free(payload); free(key); if (payload_b64 != id_or_payload) free(payload_b64); return; }

        unsigned char iv[AES_IV_LEN];
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            fprintf(stderr, "Error: Could not generate IV.\n");
            free(payload); free(key); free(file_contents); if (payload_b64 != id_or_payload) free(payload_b64); return;
        }

        int encrypted_len;
        unsigned char* encrypted_content = encrypt_aes((unsigned char*)file_contents, file_len, key, iv, &encrypted_len);
        
        char* iv_b64 = base64_encode(iv, AES_IV_LEN);
        char* encrypted_b64 = base64_encode(encrypted_content, encrypted_len);

        char final_payload[strlen(iv_b64) + strlen(encrypted_b64) + 20];
        sprintf(final_payload, "0.1.1,%s,%s", iv_b64, encrypted_b64);

        char* final_payload_b64 = base64_encode((unsigned char*)final_payload, strlen(final_payload));

        char output_buffer[strlen(name) * 3 + strlen(final_payload_b64) + 100];
        sprintf(output_buffer, "<?php // @%s\nif (! extension_loaded('%s')) exit('The \"%s\" extension is not loaded');\n#%s", name, name, name, final_payload_b64);

        if (write_file(filename, output_buffer, strlen(output_buffer))) {
            printf("Successfully encrypted: %s\n", filename);
        }

        free(file_contents); free(encrypted_content); free(iv_b64); free(encrypted_b64); free(final_payload_b64);

    } else if (strcmp(command, "decrypt") == 0) {
        long file_len;
        char* file_contents = read_file(filename, &file_len);
        if (!file_contents) { free(payload); free(key); if (payload_b64 != id_or_payload) free(payload_b64); return; }

        char* encrypted_part = strchr(file_contents, '#');
        if (!encrypted_part) {
            fprintf(stderr, "Error: Encryption signature not found in file.\n");
            free(payload); free(key); free(file_contents); if (payload_b64 != id_or_payload) free(payload_b64); return;
        }
        encrypted_part++;

        int decoded_len;
        unsigned char* decoded_data = base64_decode(encrypted_part, &decoded_len);
        
        strtok((char*)decoded_data, ",");
        char* iv_b64 = strtok(NULL, ",");
        char* encrypted_b64 = strtok(NULL, ",");

        if (!iv_b64 || !encrypted_b64) {
             fprintf(stderr, "Error: Invalid encrypted data format.\n");
             free(payload); free(key); free(file_contents); free(decoded_data); if (payload_b64 != id_or_payload) free(payload_b64); return;
        }

        int iv_len, encrypted_len;
        unsigned char* iv = base64_decode(iv_b64, &iv_len);
        unsigned char* encrypted_content = base64_decode(encrypted_b64, &encrypted_len);

        int decrypted_len;
        unsigned char* decrypted_content = decrypt_aes(encrypted_content, encrypted_len, key, iv, &decrypted_len);

        if (write_file(filename, (char*)decrypted_content, decrypted_len)) {
            printf("Successfully decrypted: %s\n", filename);
        }

        free(file_contents); free(decoded_data); free(iv); free(encrypted_content); free(decrypted_content);
    }

    free(payload);
    free(key);
    if (payload_b64 != id_or_payload) {
        free(payload_b64);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s generate <name> [optional_output_file]\n", argv[0]);
        fprintf(stderr, "  %s <encrypt|decrypt> <app_name|payload_base64> <file>\n", argv[0]);
        return 1;
    }

    char* command = argv[1];

    if (strcmp(command, "generate") == 0) {
        run_generate(argc, argv);
    } else if (strcmp(command, "encrypt") == 0 || strcmp(command, "decrypt") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s <encrypt|decrypt> <app_name|payload_base64> <file>\n", argv[0]);
            return 1;
        }
        run_encrypt_decrypt(argc, argv);
    } else {
        fprintf(stderr, "Error: Unknown command '%s'. Available: generate, encrypt, decrypt.\n", command);
        return 1;
    }

    return 0;
}
