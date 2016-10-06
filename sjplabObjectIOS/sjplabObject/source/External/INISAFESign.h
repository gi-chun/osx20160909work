#ifndef __INISAFESIGN_H__

#include <time.h>

#ifdef _INI_BADA
#include "ISL_bada.h"
#endif /* _INI_BADA */

#ifdef  __cplusplus
extern "C" {
#endif /*#ifdef  __cplusplus*/

#ifndef INISAFESIGN_API
#if defined(WIN32) || defined(WINCE)
#ifdef INISAFESIGN_API_EXPORTS
#define INISAFESIGN_API __declspec(dllexport)
#elif defined(INISAFENET_API_STATIC)
#define INISAFESIGN_API
#else
#define INISAFESIGN_API __declspec(dllimport)
#endif
#else
#define INISAFESIGN_API
#endif
#endif /* INISAFESIGN_API */

#ifdef WIN32
#if defined(_INI_BADA) || defined(_WIN8STORE)
#define STDCALL
#else
#define STDCALL __stdcall
#endif /* _INI_BADA */
#else
#define STDCALL
#endif


#if defined(WIN32) || defined(WINCE)
#define INISAFESIGN_CHAR_API INISAFESIGN_API char* STDCALL  
#define INISAFESIGN_VOID_API INISAFESIGN_API void STDCALL
#define INISAFESIGN_INT_API INISAFESIGN_API int STDCALL
#else
#define INISAFESIGN_CHAR_API INISAFESIGN_API char*  
#define INISAFESIGN_VOID_API INISAFESIGN_API void
#define INISAFESIGN_INT_API INISAFESIGN_API int
#endif



#define CS_CERTSIZE				4096
/*** Encoding type ***/
#define ISL_PEM					0x31
#define ISL_DER					0x30
#define ISL_B64_ENCODE			0x00
#define ISL_B64_LF_ENCODE       0x01 

/*** RSA Padding Mode ***/
#define ISL_NO_PAD				0x00
#define ISL_RSASSA_PKCS1_15		0x01
#define ISL_RSASSA_PSS			0x02

/**for CMS Enveloped data_oid **/
#define ISL_OID_P7_DATA                     21
#define ISL_OID_P7_SIGNED_DATA              22
#define ISL_OID_P7_ENVELOPEDDATA            23
#define ISL_OID_P7_SIGNEDANDENVELOPEDDATA   24
#define ISL_OID_P7_DIGESTDATA               25
#define ISL_OID_P7_ENCRYPTEDDATA            26

/*for CMS Version */
#define ISL_CMS_VER_1	1
#define ISL_CMS_VER_3	3

/*** PKCS7 version ***/
#define ISL_PK7_VER_14	0
#define ISL_PK7_VER_15  1

/*** Success Code ***/
#define ISL_OK		0

#ifdef _WIN8STORE
#define ISL_RSAES_PKCS1_15 0x20
#define ISL_RSAES_OAEP_20 0x08
#define ISL_RSAES_OAEP_21 0x10
#endif


typedef struct _INISAFESIGN_CONF_CTX 
{
    char servercertpath[256];
    char serverprvkey[256];
    char serverprvpass[256];
    char serveralg[256];
	char digestname[256];
	char web6path[256];
}INISAFESIGN_CONF_CTX;

/**
 * @brief   : 
 * @param   :() : 
 */
INISAFESIGN_VOID_API ISL_print_time(char *msg, FILE *fp);


INISAFESIGN_INT_API ISL_Read_File(char *filename, unsigned char **out, int *outlen);

/**
 * @brief   : 
 * @param   :() : 
 */
INISAFESIGN_VOID_API ISL_HexaDump(FILE *out, unsigned char *content, int len);

/**
 * @brief   : 
 * @param   :() : 
 */
INISAFESIGN_VOID_API ISL_Change_Non_Proven(void);

/**
 * @brief   : 
 * @param   :() : 
 */
INISAFESIGN_INT_API ISL_Initialize(char *conf_path, char *license_path );



/**
 * @brief   : 
 * @param   :() : 
 */
INISAFESIGN_VOID_API ISL_Cleanup(void);

/**
 * @brief   : 
 * @param   :(char *) : 
 * @param   :(char *) : 
 * @param   :(int) : 
 * @param   :(char *) : license file 경로. ASP 일경우 Configure 경로
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_Log_Init(char *path, char *name, int level);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_VOID_API ISL_Log_Close();

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_VOID_API ISL_Free(unsigned char *str);

/**
 * @brief   : 
 * @param   :(int) out_type : 인코딩 타입.
 *           ICL_PEM | ICL_DER | ICL_B64_ENCODE
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Signed_Path(char *cert_path, char *pkey_path, char *passwd, char* hash_alg, unsigned char *indata, int indata_len, int sign_ver, int out_type, unsigned char **outdata, int *outdata_len);


/**
 * @brief   : 
 * @param   :(int) out_type : 인코딩 타입.
 *           ICL_PEM | ICL_DER | ICL_B64_ENCODE
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Signed(unsigned char *cert_str, int cert_len, unsigned char *pkey_str, int pkey_len, char *passwd, char* hash_alg,  unsigned char *indata, int indata_len, int sign_ver, int out_type,  unsigned char **outdata, int* outdata_len);

/**
 * @brief   : 
 * @param   :(int) out_type : 인코딩 타입.
 *           ICL_PEM | ICL_DER | ICL_B64_ENCODE
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Add_Signed_Path(char *cert_path, char *pkey_path, char *passwd, char* hash_alg, struct tm *recv_time, unsigned char *indata, int indata_len, int sign_ver, int out_type, unsigned char **outdata, int *outdata_len);


/**
 * @brief   : 
 * @param   :(int) out_type : 인코딩 타입.
 *           ICL_PEM | ICL_DER | ICL_B64_ENCODE
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Add_Signed(unsigned char *cert_str, int cert_len, unsigned char *pkey_str, int pkey_len, char *passwd, char* hash_alg, struct tm *recv_time,  unsigned char *indata, int indata_len, int sign_ver, int out_type,  unsigned char **outdata, int* outdata_len);


#ifdef _WIN8STORE
INISAFESIGN_INT_API ISL_P7_Add_Signed_W8App(unsigned char *cert_str, int cert_len, unsigned char *pkey_str, int pkey_len, char *passwd, char* hash_alg, char *str_recv_time,  unsigned char *indata, int indata_len, int sign_ver, int out_type,  unsigned char **outdata, int* outdata_len);
#endif

/**
 * @brief   : 
 * @param   :() 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Verify_Signed(unsigned char *p7data, int p7data_len, unsigned char** outdata, int *outdata_len);

/**
 * @brief   : 
 * @param   :() 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Verify_B64Enc_Signed(unsigned char *p7data, int p7data_len, unsigned char **outdata, int *outdata_len);

/**
 * @brief   : 
 * @param   :() 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Get_EncDigest_PubKey(unsigned char *p7data, int p7data_len, int index, unsigned char **out_encdig, int *out_encdig_len, unsigned char **out_pubkey, int *out_pubkey_len);
INISAFESIGN_INT_API ISL_P7_B64_Get_EncDigest_PubKey(unsigned char *p7data, int p7data_len, int index, unsigned char **out_encdig, int *out_encdig_len, unsigned char **out_pubkey, int *out_pubkey_len);

/**
 * @brief   : PEM 또는 DER 형태의 pkcs7 서명데이터에서 signer의 갯수를 뽑는다.
 * @param   :(unsigned char*) p7data : PEM 또는 DER 형태의 pkcs7 서명 데이터
 * @param   :(int) p7datalen : PEM 또는 DER 형태의 pkcs7 서명 데이터 길이.
 * @param   :(int*) count : signer 갯수.
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Get_SignerCnt(unsigned char *p7data, int p7datalen, int *count);

/**
 * @brief   : BASE64 형태의 pkcs7 서명데이터에?signer의 갯수를 뽑는다.
 * @param   :(unsigned char*) p7data : BASE64 형태의 pkcs7 서명 데이터.
 * @param   :(int) p7datalen : BASE64 형태의 pkcs7 서명 데이?길이.
 * @param   :(int*) count : signer 갯수.
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_B64_Get_SignerCnt(unsigned char *p7data, int p7datalen, int *count);

/**
 * @brief   : DER 또는 PEM 형태의 pkcs7 서명데이터에 index 번째 Sign time 을 뽑는다.
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Get_SignTime(unsigned char *p7data, int p7datalen, int index, char** sign_time_out, int *time_out_len);

/**
 * @brief   : BASE64 형태의 pkcs7 서명데이터에서 index번째 Sign time 을 뽑는다
 * @param   :(unsigned char*) p7data : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_B64_Get_SignTime(unsigned char *p7data, int p7datalen, int index, char** sign_time_out, int *time_out_len);

/**
 * @brief   :PEM 또는 DER 형태의 pkcs7 서명데이터에펣igner cer sign time 을甄쨈?
 * @param   :(unsigned char*) p7data : PEM 또는 DER 형태의  pkcs7 서명 데이터.
 * @param   :(int) p7datalen : pkcs7 서명 데이터 길이.
 * @param   :(int) index : 뽑아낼 info 의 index 
 * @param   :(unsigned char**) signer_cert : out_cert_type 형태의 signercert (return)
 * @param   :(int*) signer_cert_len : signer cert 의 길이. (return)
 * @param   :(int) out_cert_type :  signer cert의 인코딩 타입
 *                                  ISL_PEM | ISL_DER | ISL_B64_ENCODE
 * @param   :(char**) sign_time: sign time (return)
 * @param   :(int*) signer_cert_len : signer cert 의 길이. (return)
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Get_SignerInfo(unsigned char *p7data, int p7datalen, int index, unsigned char** signer_cert, int *signer_cert_len, int out_cert_type, char **sign_time, int *sign_time_len);

/**
 * @brief   :BASE64 형태의 pkcs7 서명데이터에펣igner cer sign time 을甄쨈?
 * @param   :(unsigned char*) p7data : BASE64형태의  pkcs7 서명 데이터.
 * @param   :(int) p7datalen : pkcs7 서명 데이터 길이.
 * @param   :(int) index : 뽑아낼 info 의 index 
 * @param   :(unsigned char**) signer_cert : out_cert_type 형태의 signercert (return)
 * @param   :(int*) signer_cert_len : signer cert 의 길이. (return)
 * @param   :(int) out_cert_type :  signer cert의 인코딩 타입
 *                                  ISL_PEM | ISL_DER | ISL_B64_ENCODE
 * @param   :(char**) sign_time: sign time (return)
 * @param   :(int*) signer_cert_len : signer cert 의 길이. (return)
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_B64_Get_SignerInfo(unsigned char *p7data, int p7datalen, int index, unsigned char** signer_cert, int *signer_cert_len, int out_cert_type, char **sign_time, int *sign_time_len);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Enveloped_Path(char *cert_path, char* cipher_alg, unsigned char *indata, int indata_len, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **outdata, int* outdata_len); 
INISAFESIGN_INT_API ISL_P7_Enveloped_Path_With_Pad(char *cert_path, char* cipher_alg, unsigned char *indata, int indata_len, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **outdata, int* outdata_len, char padmode);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Enveloped(unsigned char *cert_str, int cert_len, char* cipher_alg, unsigned char *indata, int indata_len, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **outdata, int* outdata_len);
INISAFESIGN_INT_API ISL_P7_Enveloped_With_Pad(unsigned char *cert_str, int cert_len, char* cipher_alg, unsigned char *indata, int indata_len, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **outdata, int* outdata_len, char padmode);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_B64_Verify_Enveloped_Path(char *cert_path, char *pkey_path, char *passwd, unsigned char *indata,int indata_len, unsigned char **sym_key,int *sym_key_len, unsigned char **sym_iv, int *sym_iv_len, unsigned char **outdata, int *outdata_len );

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */

INISAFESIGN_INT_API ISL_P7_B64_Verify_Enveloped(unsigned char *cert_str, int cert_len, unsigned char *pkey_str, int pkey_len, char *passwd, unsigned char *indata,int indata_len, unsigned char **sym_key, int *sym_key_len, unsigned char **sym_iv, int *sym_iv_len, unsigned char **outdata, int *outdata_len );

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Verify_Enveloped_Path(char *cert_path, char *pkey_path, char *passwd, unsigned char *indata,int indata_len, unsigned char **sym_key, int *sym_key_len, unsigned char **sym_iv,int *sym_iv_len, unsigned char **outdata, int *outdata_len );


/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Verify_Enveloped(unsigned char *cert_str, int cert_len, unsigned char *pkey_str, int pkey_len, char *passwd, unsigned char *indata,int indata_len, unsigned char **sym_key, int *sym_key_len, unsigned char **sym_iv, int *sym_iv_len, unsigned char **outdata, int *outdata_len );

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Signed_And_Enveloped_Path(char *signer_cert_path, char *signer_pkey_path, char *passwd, unsigned char *recp_cert_str, int recp_cert_len, unsigned char *indata, int indata_len, char *hash_alg, char *cipher_alg, unsigned char *sym_key,  unsigned char *sym_iv, int out_type, unsigned char **outdata, int *outdata_len);
INISAFESIGN_INT_API ISL_P7_Signed_And_Enveloped_Path_With_Pad(char *signer_cert_path, char *signer_pkey_path, char *passwd, unsigned char *recp_cert_str, int recp_cert_len, unsigned char *indata, int indata_len, char *hash_alg, char *cipher_alg, unsigned char *sym_key,  unsigned char *sym_iv, int out_type, unsigned char **outdata, int *outdata_len, char padmode);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Signed_And_Enveloped(unsigned char *signer_cert_str, int signer_cert_len, unsigned char *signer_pkey_str, int signer_pkey_len, char *passwd, unsigned char *recp_cert_str, int recp_cert_len, unsigned char *indata, int indata_len,  char *hash_alg, char *cipher_alg, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **outdata, int *outdata_len);
INISAFESIGN_INT_API ISL_P7_Signed_And_Enveloped_With_Pad(unsigned char *signer_cert_str, int signer_cert_len, unsigned char *signer_pkey_str, int signer_pkey_len, char *passwd, unsigned char *recp_cert_str, int recp_cert_len, unsigned char *indata, int indata_len,  char *hash_alg, char *cipher_alg, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **outdata, int *outdata_len, char padmode);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Verify_Signed_And_Enveloped_Path(char *cert_path, char *pkey_path, char *passwd, unsigned char *indata, int indata_len, unsigned char **sym_key, int *sym_key_len, unsigned char **sym_iv, int *sym_iv_len, unsigned char **outdata, int *outdata_len);


/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_Verify_Signed_And_Enveloped(unsigned char *cert_str, int cert_len,  unsigned char *pkey_str, int pkey_len, char *passwd, unsigned char *indata, int indata_len, unsigned char **sym_key, int *sym_key_len, unsigned char **sym_iv, int *sym_iv_len, unsigned char **outdata, int *outdata_len);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_B64_Verify_Signed_And_Enveloped_Path(char *cert_path, char *pkey_path, char *passwd, unsigned char *indata, int indata_len, unsigned char **sym_key, int *sym_key_len, unsigned char **sym_iv, int *sym_iv_len, unsigned char **outdata, int *outdata_len);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_P7_B64_Verify_Signed_And_Enveloped(unsigned char *cert_str, int cert_len,  unsigned char *pkey_str, int pkey_len, char *passwd, unsigned char *indata, int indata_len, unsigned char **sym_key, int *sym_key_len, unsigned char **sym_iv, int *sym_iv_len, unsigned char **outdata, int *outdata_len);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_Sym_Encrypt(unsigned char *indata, int indata_len, char* cipher_alg, unsigned char* key, unsigned char* iv, int out_type,  unsigned char **outdata,  int *outdata_len);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_Sym_Decrypt(int in_type, unsigned char *indata, int indata_len, char *cipher_alg, unsigned char *key, unsigned char *iv, unsigned char **outdata, int *outdata_len);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_Get_CertInfo(unsigned char *cert_str, int cert_str_len, char *indata,int indata_len, char *outdata, int *outdata_len);

/** 
 * @brief   : get private-key from priv_str and make signature with it.(RSA | KCDSA) 
 * @param   :(unsigned char *) priv_str: read privkey-string (PKCS#1 or  PKCS#8, PEM or DER) 
 * @param   :(int) priv_len: length of priv_str  
 * @param   :(char *) passwd: private-key password  (if not encrypted file, input NULL)  
 * @param   :(int) passwd_len: length of passwd     (if not encrypted file, input 0) 
 * @param   :(unsigned char *) pad_mode: padding-mode 
 *          ISL_NO_PAD      : no padding (in_len = length of RSA key) 
 *          ISL_RSASSA_PKCS1_15: RSASSA_PKCS1_v1.5 padding 
 *          ISL_RSASSA_PSS  : RSASSA_PSS padding 
 * @param   :(char *) hash_alg: hash algorithm name 
 *          ("MD5" | "SHA1" | "SHA224" * | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2") 
 * @param   :(unsigned char *) in: plaintext 
 * @param   :(int) in_len: length of in 
 * @param   :(unsigned char **) outdata: signature. (return) 
 * @param   :(int *) outdata_len: length of out (return) 
 * @return  :(int) success=0, error=error code 
 */

INISAFESIGN_INT_API ISL_PK1_Sign(unsigned char *priv_str, int priv_len, char *passwd, int passwd_len, char pad_mode, char *hash_alg, unsigned char *in, int in_len, unsigned char **outdata, int *outdata_len);

/** 
 * @brief   : get public-key from pubk_str and verify signature with it. (RSA | KCDSA) 
 * @param   :(unsigned char *) pubk_str: read PKCS#1 public-key string (PKCS#1 or CERT, PEM or DER) 
 * @param   :(int) pubk_len: length of pubk_str  
 * @param   :(unsigned char *) pad_mode: padding-mode 
 *          ISL_NO_PAD      : no padding (in_len = length of RSA key) 
 *          ISL_RSASSA_PKCS1_15: RSASSA_PKCS1_v1.5 padding 
 *          ISL_RSASSA_PSS  : RSASSA_PSS padding  
 * @param   :(char *) hash_alg: hash algorithm name 
 *              ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2") * 
 * @param   :(unsigned char *) msg: plaintext
 * @param   :(int) msg_len: length of msg 
 * @param   :(unsigned char *) sign: signature 
 * @param   :(int *) sign_len: length of sign 
 *  
 * @return  :(int) success=0, error=error code 
 */
INISAFESIGN_INT_API ISL_PK1_Verify(unsigned char *pubk_str, int pubk_len, char pad_mode, char *hash_alg, unsigned char *msg, int msg_len, unsigned char *sign, int sign_len);


/** 
 * @brief   : 금결원 전자채권 용 서명 api
 * @param   :(char *) cert_str: 인증서 
 * @param   :(int ) cert_len: 인증서 length
 * @param   :(char *) pkey_str: 개인키 
 * @param   :(char *) pkey_len: 개인키 length
 * @param   :(char *) passwd: 개인키 비밀번호
 * @param   :(char *) hash_alg: 서명시 사용되는 해쉬 알고리즘 명
 *              ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2") * 
 * @param   :(unsigned char *) indata: 서명할 데이터
 * @param   :(int) indata_len: 서명할 데이터 길이
 * @param   :(int) sign_ver: 서명 버전 (ISL_PK7_VER_15)
 * @param   :(int) rm_content_flag: content info 를 없앨것인지 여부(0|1).
 *  
 * @return  :(int) success=0, error=error code 
 */
INISAFESIGN_INT_API ISL_KFTC_Signed(unsigned char *cert_str, int cert_len, unsigned char *pkey_str, int pkey_len, char *passwd, char *hash_alg, unsigned char *indata,int indata_len, int sign_ver, int rm_content_flag, int out_type, unsigned char **outdata, int *outdata_len);

/** 
 * @brief   : 금결원 전자채권 용 서명 api
 * @param   :(char *) cert_path: 인증서 파일 경로
 * @param   :(char *) pkey_path: 개인키 파일 경로
 * @param   :(char *) enc_pass_path: 암호화된 개인키 패스워드 파일 경로.
 * @param   :(char *) hash_alg: 서명시 사용되는 해쉬 알고리즘 명
 *              ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2") * 
 * @param   :(unsigned char *) msg: 서명할 데이터
 * @param   :(int) msg_len: 서명할 데이터 길이
 * @param   :(int) sign_ver: 서명 버전 (ISL_PK7_VER_15)
 * @param   :(int) rm_content_flag: content info 를 없앨것인지 여부(0|1).
 * 테스트시 플래그를 1로 입력 하여 pkcs7정상 데이터를 받아 테스트하도록 한다.
 *  
 * @return  :(int) success=0, error=error code 
 */

INISAFESIGN_INT_API ISL_KFTC_Signed_Path(char *cert_path, char *pkey_path, char *enc_pass_path, char *hash_alg, unsigned char *indata,int indata_len, int sign_ver, int rm_content_flag ,unsigned char **outdata, int *outdata_len);


/** 
 * @brief   : 금결원 전자채권 용 서명 api
 * @param   :(char *) cert_path: 인증서 파일 경로
 * @param   :(char *) pkey_path: 개인키 파일 경로
 * @param   :(char *) enc_pass_path: 암호화된 개인키 패스워드 파일 경로.
 * @param   :(char *) hash_alg: 서명시 사용되는 해쉬 알고리즘 명
 *              ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2") * 
 * @param   :(unsigned char *) msg: 서명할 데이터
 * @param   :(int) msg_len: 서명할 데이터 길이
 * @param   :(int) sign_ver: 서명 버전 (ISL_PK7_VER_15)
 * @param   :(int) rm_content_flag: content info 를 없앨것인지 여부(0|1).
 * 테스트시 플래그를 1로 입력 하여 pkcs7정상 데이터를 받아 테스트하도록 한다.
 *  
 * @return  :(int) success=0, error=error code 
 */
INISAFESIGN_INT_API ISL_KFTC_Signed_By_SmartCard(int type, char *serialdev, char *pass_path, char *hash_alg, char *pinnum, unsigned char *indata , int indata_len, int sign_ver,  int rm_content_flag, unsigned char **outdata, int *outdata_len);


/**
 * @brief   : Base64 encoding. using INICrypto_v5
 * @param   :(unsigned char *) indata: data to encode
 * @param   :(int) indata_len: length of data
 * @param   :(char **) base64: encoded data with BASE-64 (return)
 * @param   :(int *) base64_len: encoded data with BASE-64 length (return)
 * @param   :(int) mode: insert linefeed flag at every 64byte.  (0=no linefeed, 1=insert linefeed)
 * @return  :(int) success=0, error=error code
 */
INISAFESIGN_INT_API ISL_TOOL_Base64_Encode(unsigned char *indata, int indata_len, char **base64, int *base64_len, int lf_mode);

/**
 * @brief   : Base64 decoding. using INICrypto_v5
 * @param   :(char *) base64: data to decode
 * @param   :(int) base64Len: length of base64
 * @param   :(unsigned char **) output: decoded data with BASE-64 (return)
 * @param   :(int *) outdata_len: decoded data with BASE-64 length (return)
 * @return  :(int) success=0, error=error code
 */
INISAFESIGN_INT_API ISL_TOOL_Base64_Decode(char *base64, int base64_len, unsigned char **outdata, int *outdata_len);

/**
 * @brief   : content info가 빠진 p7데이터에 content info 를 삽입
 * 	      펜타 시큐리티 p7 데이터 호환을 위해 개발됨.
 * @param   :(unsigned char *) indata: content info 가 빠진 p7데이터 
 * @param   :(int) indata_len: indata의 길이.
 * @param   :(int) oid_type: 	1:data
 * 				2:signedData
 * 				3:envelopedData
 * 				4:signedAndEnvelopedData
 * 				5:digestedData
 * 				6:encryptedData 
 * @param   :(unsigned char **) output: 삽입된 정상 포맷의 p7 data (return)
 * @param   :(int *) outdata_len: outdata 의 길이 (return)
 * @return  :(int) success=0, error=error code
 */
INISAFESIGN_INT_API ISL_Insert_Content(unsigned char *indata, int indata_len, int oid_type, unsigned char **outdata, int *outdata_len  );


/**
 * @brief   :정상 p7데이터에서 content info 를 제거 하여 반환. 
 * @param   :(unsigned char *) indata: p7 데이터
 * @param   :(int) indata_len: p7 데이터의 길이
 * @param   :(unsigned char **) output: content info 가 제거된 p7 데이터 (return)
 * @param   :(int *) outdata_len: outdata 의 길이 (return)
 * @return  :(int) success=0, error=error code
 */
INISAFESIGN_INT_API ISL_Remove_Content(unsigned char *indata, int indata_len, unsigned char **outdata, int *outdata_len);




/*************************************************************************************
 * Old Function
 * v1.x
 **************************************************************************************/

/**
 * @brief   : old initailze function
 * @param   :() : 
 */
INISAFESIGN_VOID_API ISL_Init(void);


/**
 * @brief   : 
 * @param   :(char *) : 
 * @param   :(char *) : 
 * @param   :(int) : 
 * @param   :(char *) : license file 경로. ASP 일경우 Configure 경로
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_LOGInit(char *path, char *name, int level, char *confpath);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_VOID_API ISL_LOGClose();

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7SignedPEM_path(char *certpath, char *pkeypath, char *pkeypasswd, char *hashAlg, unsigned char *indata, int indatalen, unsigned char **outdata, int* outdatalen);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7SignedPEM(unsigned char *cert, int certlen, unsigned char *pkeystr, int pkeylen, char *pkeypasswd, char* hashAlg,  unsigned char *indata, int indatalen, unsigned char **outdata, int* outdatalen);


/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7SignedBASE64_path(char *certpath, char *pkeypath, char *pkeypasswd, char *hashAlg, unsigned char *indata, int indatalen, unsigned char **outdata, int* outdatalen);


/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7SignedBASE64(unsigned char *cert, int certlen, unsigned char *pkey, int pkeylen, char *pkeypasswd, char* hashAlg, unsigned char *indata, int indatalen, unsigned char **outdata, int* outdatalen);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7SignedASN1_path(char *certpath, char *pkeypath, char *pkeypass, char * hashAlg, unsigned char *data, int datalen, unsigned char **signeddata, int *signeddatal);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7SignedASN1(unsigned char *cert,int certlen, unsigned char *pkeystr,int pkeylen, char *pkeypass, char * hashAlg, unsigned char *data, int datalen, unsigned char **signeddata, int *signeddatal);

/**
 * @brief   :DER 또는 PEM 타입의 pkcs7 서명 데이터를 검증한다.
 * @param   :(unsigned char*) p7data: DER 또는 PEM 타입의  pkcs7 서명 데이터.
 * @param   :(int) p7datalen: pkcs7 서명 데이터 길이.
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7SignedVerify(unsigned char *p7data,int p7datalen);

/**
 * @brief   :BASE64 인코딩된 pkcs7 서명 데이터를 검증한다.
 * @param   :(unsigned char*) p7data: BASE64 인코딩된 pkcs7 서명 데이터.
 * @param   :(int) p7datalen: BASE64 인코딩된 pkcs7 서명 데이터 길이.
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7BASE64SignedVerify(unsigned char *p7data,int p7datalen);

/**
 * @brief   :BASE64 형태의 pkcs7 서명데이터를 검증하고 원문 데이?* 뽑는다.
 * @param   :(unsigned char*) p7data : BASE64 형태의 pkcs7 서?데이터. 
 * @param   :(nt) p7datalen : BASE64 형태의 pkcs7 서?데이 길이. 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7SignedBase64VerifyGetOrgData(unsigned char *p7data,int p7datalen, unsigned char** outdata, int *outdatalen);

/**
 * @brief   :DER 또는 PEM 형태의 pkcs7 서명데이터를 검증하고 원문 데이?* 뽑는다.
 * @param   :(unsigned char*) p7data : DER 또는 PEM 형태의 pkcs7 서?데이터. 
 * @param   :(nt) p7datalen : DER 또는 PEM 형태의 pkcs7 서?데이 길이. 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7SignedVerifyGetOrgData(unsigned char *p7data, int p7datalen, unsigned char** outdata, int *outdatalen);

/**
 * @brief   : DER 또는 PEM 형태의 pkcs7 서명데이터에서 Sign time 을 뽑는다.
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7SignedDataGetSignTime(unsigned char *p7data, int p7datalen, char** signtime, int *signtimelen);

/**
 * @brief   : DER 또는 PEM 형태의 pkcs7 서명데이터에서 Sign time 을 뽑는다.
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7SignedDataGetSignerCert(unsigned char *p7data, int p7datalen, char** signercert, int *signercertlen);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7EnvelopedEncryptPEM_path(char *certpath, char *ciphername, unsigned char *indata, int indatalen, unsigned char **outdata, int* outdatalen);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7EnvelopedEncryptPEM(unsigned char *cert, int certlen, char* ciphername, unsigned char *indata, int indatalen, unsigned char **outdata, int* outdatalen);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7EnvelopedEncryptBASE64_path(char *certpath, char* ciphername, unsigned char *indata, int indatalen, unsigned char **outdata, int* outdatalen);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7EnvelopedEncryptBASE64(unsigned char *cert, int certlen, char* ciphername, unsigned char *indata, int indatalen, unsigned char **outdata, int* outdatalen);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7EnvelopedEncryptASN1(unsigned char *cert, int certlen, unsigned char *data, int datalen, char *ciphername, unsigned char **envelopeddata, int *envelopeddatalen);
/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7EnvelopedEncWithKeyIVBASE64(unsigned char *cert, int certlen, char* ciphername, unsigned char *skey, unsigned char *iv, unsigned char *indata, int indatalen, unsigned char **outdata, int* outdatalen);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7EnvelopedEncWithKeyIVPEM(unsigned char *cert, int certlen, char* ciphername, unsigned char *skey, unsigned char *iv, unsigned char *indata, int indatalen, unsigned char **outdata, int* outdatalen);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7EnvelopedDecryptBASE64_path(char *certpath, char *pkeypath, char *pkeypasswd, unsigned char *p7data,int p7datalen, unsigned char** out, int* outl );

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7EnvelopedDecrypt(unsigned char *cert, int certlen,  unsigned char *pkey, int pkeylen, char *pkeypasswd, unsigned char *p7data,int p7datalen, unsigned char** out, int* outl );

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7EnvelopedDecrypt_path(char *certpath, char *pkeypath, char *pkeypasswd, unsigned char *p7data,int p7datalen, unsigned char** out, int* outl );

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7EnvelopedDecWithKeyIV_path(char *certpath, char *pkeypath, char *pkeypasswd ,unsigned char *p7data,int p7datalen, unsigned char** out, int* outl ,unsigned char *outskey, unsigned char *outiv);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_SymEncryptWithBase64(unsigned char **out, unsigned char *data, char* ciphername, unsigned char* key, unsigned char* iv);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_SymDecryptWithBase64(unsigned char **out, unsigned char *data, int inl, char* ciphername, unsigned char* key, unsigned char* iv);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_VOID_API ISL_String_free(char *indata);

#ifdef INITECH_ASP
/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
int ISL_Init_Env(INISAFESIGN_CONF_CTX* g_conf_ctx, char *configfile);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7Signed_confpath(unsigned char *indata, char* cert_path, char* pkey_path, char* passwd, char* digestname, unsigned char **outdata, int *outdata_len, int out_type);

#else
/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
int ISL_Init_Env(char *configfile);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_PKCS7Signed_confpath(unsigned char *indata, int indatalen, unsigned char **outdata, int *outdatalen, int type);
#endif

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_GetCertInfo(unsigned char *cert, char *indata, char *outdata);

/**
 * @brief   : 
 * @param   :() : 
 * @return  :() success:0 or error_code
 */
INISAFESIGN_INT_API ISL_Util_Check_VID(unsigned char *cert_str, int cert_str_len, unsigned char *rand, int rand_len, char *ssn, int ssn_len);

/* winstore edith */
#if defined(WIN32) && !defined(_WIN8STORE)
INISAFESIGN_INT_API ISL_PKCS7SignedFromCertUI(char* logoPath, unsigned char* indata, int indatalen, const char *certfilter,  const char* hashAlg, unsigned char** outdata, int *outdatalen);
int ISL_SelectCert(char* logoPath, const char* filter,  unsigned char* pCert, int *pCertLen,			
				   unsigned char* pCertPri,  int *pCertPriLen, char* pPassword, int *pPasswordLen);

INISAFESIGN_INT_API ISL_RSASignedVerify(unsigned char *indata,int indatalen, unsigned char *sig, int siglen, char *mdname, char* cert, int certlen);
INISAFESIGN_INT_API ISL_SetProperty(const char* name, const char* value);
INISAFESIGN_INT_API ISL_PKCS7SignedFromCache(unsigned char* indata, int indatalen, const char* hashAlg, unsigned char** outdata, int *outdatalen);
INISAFESIGN_INT_API ISL_PKCS7EnvelopedDecryptFromCertUI(char* logoPath, unsigned char* indata, int indatalen, const char *certfilter,  unsigned char** outdata, int *outdatalen);
INISAFESIGN_INT_API ISL_PKCS7EnvelopedDecryptFromCache(unsigned char* indata, int indatalen, unsigned char** outdata, int *outdatalen);
INISAFESIGN_INT_API ISL_PKCS7CheckCertUI(char* logoPath, const char *certfilter);
INISAFESIGN_INT_API ISL_PKCS7CheckPrivateKeyPassword(char* indata);
INISAFESIGN_INT_API ISL_GetCacheCert(char* outdata);
#endif


#ifndef INITECH_ASP
INISAFESIGN_INT_API ISL_GetLastError();
#endif

INISAFESIGN_CHAR_API ISL_GetErrorString(int result);



// API for CMS

INISAFESIGN_INT_API ISL_CMS_Signed(unsigned char *cert_str, int cert_len, unsigned char *pkey_str, int pkey_len, char *passwd, char pad_mode, char* hash_alg,  unsigned char *indata, int indata_len, int sign_ver, int out_type,  unsigned char **outdata, int* outdata_len);
INISAFESIGN_INT_API ISL_CMS_Signed_Path(char *cert_path, char *pkey_path, char *passwd, char pad_mode, char* hash_alg, unsigned char *indata, int indata_len, int sign_ver, int out_type, unsigned char **outdata, int *outdata_len);
INISAFESIGN_INT_API ISL_CMS_Verify_Signed(int in_type, unsigned char *cmsdata, int cmsdata_len, unsigned char** outdata, int *outdata_len);

INISAFESIGN_INT_API ISL_CMS_Enveloped(unsigned char *cert_str, int cert_len, char* cipher_alg, unsigned char *indata, int indata_len, int data_oid, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **outdata, int* outdata_len);
INISAFESIGN_INT_API ISL_CMS_Enveloped_With_Pad(unsigned char *cert_str, int cert_len, char* cipher_alg, unsigned char *indata, int indata_len, int data_oid, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **outdata, int* outdata_len, char padmode);
INISAFESIGN_INT_API ISL_CMS_Enveloped_Path(char *cert_path, char* cipher_alg, unsigned char *indata, int indata_len, int data_oid, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **outdata, int* outdata_len);
INISAFESIGN_INT_API ISL_CMS_Enveloped_Path_With_Pad(char *cert_path, char* cipher_alg, unsigned char *indata, int indata_len, int data_oid, unsigned char *sym_key, unsigned char *sym_iv, int out_type, unsigned char **outdata, int* outdata_len, char padmode);
INISAFESIGN_INT_API ISL_CMS_Verify_Enveloped(int in_type, unsigned char *cert_str, int cert_len, unsigned char *pkey_str, int pkey_len, char *passwd, unsigned char *indata,int indata_len, unsigned char **sym_key, int *sym_key_len, unsigned char **sym_iv, int *sym_iv_len, unsigned char **outdata, int *outdata_len );
INISAFESIGN_INT_API ISL_CMS_Verify_Enveloped_Path(int in_type, char *cert_path, char *pkey_path, char *passwd, unsigned char *indata,int indata_len, unsigned char **sym_key, int *sym_key_len, unsigned char **sym_iv, int *sym_iv_len, unsigned char **outdata, int *outdata_len );

INISAFESIGN_INT_API ISL_CMS_Get_SignerCnt(int in_type, unsigned char *cmsdata, int cmsdatalen, int *count);
INISAFESIGN_INT_API ISL_CMS_Get_SignTime(int in_type, unsigned char *cmsdata, int cmsdatalen, int index, char** sign_time_out, int *time_out_len);
INISAFESIGN_INT_API ISL_CMS_Get_SignerInfo(int in_type, unsigned char *cmsdata, int cmsdatalen, int index, unsigned char** signer_cert, int *signer_cert_len, int out_cert_type, char **sign_time, int *sign_time_len);


#ifdef  __cplusplus
}
#endif /*#ifdef  __cplusplus*/


#endif
