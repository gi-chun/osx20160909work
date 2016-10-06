#define _IPHONE 1
#ifndef __INISAFEXSAFE_H__
#define __INISAFEXSAFE_H__

#ifdef _INI_BADA
#include "IXL_bada.h"
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef INISAFEXSAFE_API
#ifdef WIN32
	#ifdef INISAFEXSAFE_EXPORTS
		#define INISAFEXSAFE_API __declspec(dllexport)
	#elif defined(INISAFEXSAFE_API_STATIC)
		#define INISAFEXSAFE_API
	#else
		#define INISAFEXSAFE_API __declspec(dllimport)
	#endif
#else
	#define	INISAFEXSAFE_API
#endif
#endif

#ifdef WINCE
#define ICL_FL 	__FILE__,__LINE__
#endif

#define BUFLEN 256

#define SKINFO_MAX_NUM 			10

#define MAX_KEY_LEN				16
#define PREMASTERSECRET			64

#define INIPLUGINVERSION		"100"
    
#define VID_MAX_LENGTH          64

/* Padding Mode */ 
#define NO_PAD_MODE				0
#define RSASSA_PKCS1_15_MODE	1
#define RSASSA_PSS_MODE			2
#define STR_RSASSA_PKCS1_15		"RSASSA_PKCS1_15"
#define STR_RSASSA_PSS			"RSASSA_PSS"

/* Algorithm */
#define STR_SEED_CBC			"SEED-CBC"
#define STR_KCDSA				"KCDSA"
#define STR_KCDSA1				"KCDSA1"
#define STR_RSA					"RSA"
#define STR_RSA15				"RSA15"
#define STR_RSA20				"RSA20"
#define STR_PSS					"PSS"
#define STR_OAEP				"OAEP"

/* Hash Algorithm */
#define HASH_SHA1				"SHA1"
#define HASH_SHA256				"SHA256"

#ifdef _WIN8STORE
#define HASH_HAS160				"HAS-160"
#else
#define HASH_HAS160				"HAS160"
#endif

/* Is Key Exist*/
#define KEY_NOT_EXIST			0
#define KEY_EXIST				1

/* Cert Type */
#define KM_CERT_TYPE            0       /* 암호용 인증서 타입 */
#define SIGN_CERT_TYPE          1       /* 사인용 인증서 타입 */
    
/* StoreType Cert Flag*/
#define ROOT_CA_CERT_FLAG		0		/* 최상위 인증 기관 */
#define ROOT_CERT_FLAG			1		/* ROOT 인증서 */
#define CA_CERT_FLAG			2		/* CA 인증서 */

#define	ENCODE_URL_OR_BASE64	1		/* 0 : BASE64 , 1 : URL , 2 : BASE64+URL */

#define ENCODE_BASE64			0		/* Base64 Encoding */
#define ENCODE_URL				1		/* URL Encoding */
#define ENCODE_BASE64_URL		2		/* BASE64+url Encoding */

#if defined(WIN32)
#ifdef WINCE
#define LOADLIBRARY			L"INISAFECMP.dll"	// sangwon.hont add : WINCE는 wide char로 동작.
#elif defined(_WIN8STORE)
#define LOADLIBRARY				"..\..\INISafeCMP.dll"	//jjm 09_25
#else
#define LOADLIBRARY				"INISAFECMP.dll"
#endif
#elif defined(_MACOS)
#define LOADLIBRARY				"libinisafeCMP.dylib"
#elif defined(HP_UX)
#define LOADLIBRARY				"libinisafeCMP.sl"
#else
#define LOADLIBRARY				"libinisafeCMP.so"
#endif

typedef struct _skidInfo
{
	unsigned char skid[20+1];
	unsigned char skey[16+1];
	unsigned char iv[16+1];

}IXLSkIdInfo;


#ifdef _IPHONE
typedef struct _certInfo
{
	char issuer[256];
	char subject[256];
	char serialNumber[256];
	char issueDate[256];
	char expireDate[256];
	char subjectDN[256];

	char certificatePoliciesOID[256];
	int expiredflag;

	char certpath[256];
	char pkeypath[256];
	unsigned char cert[4096];
	int certlen;
	unsigned char pkey[4096];
	int pkeylen;
	int idx;
}__attribute__((packed)) IXLCertInfo;
    

#else
typedef struct _certInfo
{
	char issuer[256];
	char subject[256];
	char serialNumber[256];
	char issueDate[256];
	char expireDate[256];
	char subjectDN[256];

	char certificatePoliciesOID[256];
	int expiredflag;

	char certpath[256];
	char pkeypath[256];
	unsigned char cert[4096];
	int certlen;
	unsigned char pkey[4096];
	int pkeylen;
	int idx;
}IXLCertInfo;
#endif


/* Cert Info Extension (mw) */
typedef struct _certInfo_ext
{
	char issuer[256];					/* 발급자 */
	char issuerDN[256];					/* 발급자 */
	char subject[256];					/* 소유자 CN */
	char serialNumber[256];				/* Serial Number */
	char certificatePoliciesOID[256];	/* OID */
	char OIDString[256];				/* OID String */
	char issueDate[256];				/* 발급 일자 */
	char expireDate[256];				/* 만료 일자 */
	char certpath[256];					/* 인증서 경로 */
	char pkeypath[256];					/* 개인키 경로 */

	char caname[256];					/* CA Name */
	int expiredflag;					/* 유효 :0 , 만료 : 1 ,갱신 : 2 */
	int nFlag;							/* 사용 : 0 , 사용 안함 : 1*/
	int ncertype;						/* 1. NPKI , 2. PPKI, 3.GPKI */



#ifdef _WIN8STORE
	// 화면에 보여주기위한 정보와
	// 필터링에 필요한 정보 두가지를 담고 있는 구조체 이다.
	char version[256];
	char signaturealg[256];
	char publickeybit[256];
	char authoritykeyid[256];
	char subjectkeyid[256];
	char keyusage[256];
	char certpolicy[256];
	char displayserial[256];
	char subjectaltname[256];
	char certpathbase64[1024];
	char subjectdn[1024];
	char fingeralg[256];
	char finger[256];
	char crldp[2048];
	char urldp[2048];
#endif


}IXLCertInfoExt;



/**< 2012.11.14 Addby hspark. */
/**< for Read Cert Path */
char selectedCertPath[1024];
/**< Get SubjectCN from USB Issue Cert */
char selectedCertSubjectCN[256];



#ifdef _WIN8STORE
/*
 *	인증서 리스트 구조체
 */
typedef struct _CertInfolist
{
	struct _certInfo_ext	*pCertInfo;
	struct _CertInfolist	*next;
}IXLCertinfolist;


typedef struct
{
	unsigned char* pCert;
	int Certlen;
}stCaCert;



/**
 *	@brief	: IXL_DeleteAllList					[ 인증서 정보 리스트 삭제 ]
 *	@param	: [IN] IXLCertinfolist* pNode		[ Root node ( Header node ) ]
 */
INISAFEXSAFE_API void IXL_DeleteAllList (IXLCertinfolist* node);
INISAFEXSAFE_API void IXL_SetStorageType(int type);
INISAFEXSAFE_API void IXL_SetStorageFolder(Windows::Storage::StorageFolder^ folder);
INISAFEXSAFE_API int IXL_SaveCert(char *certpath, char *keypath, int keyusage, int storagetype);
INISAFEXSAFE_API int IXL_MakeCertListForWin8(IXLCertinfolist** pRoot_list);
INISAFEXSAFE_API int IXL_PKCS12_Make(int encodetype, char* pECertPath, int nECertPathlen, unsigned char* pPassword, int nPasswordlen, unsigned char **pPKCS12, int *pPKCS12len);
INISAFEXSAFE_API int IXL_GetSujectDnFromCert(char* pCertData, int nCertDatalen, char** pOutData);
INISAFEXSAFE_API int IXL_PKCS1_Private_Sign (char* ecertpath,  unsigned char* pwd,int pwdl, unsigned char* org_data, int org_datal, int encodingflag, unsigned char** signoutdata, int* signoutdatal, unsigned char** outrandom, int* outrandoml);
INISAFEXSAFE_API char* IXL_GetDebugMsg();
INISAFEXSAFE_API int IXL_Set_gFilter_Win8 (unsigned char* pInFilter , int nInFilterlen);
INISAFEXSAFE_API int IXL_Delete_gFilter_Win8();
INISAFEXSAFE_API int IXL_CMPLogInit(char *path, char *name, int level);
INISAFEXSAFE_API void IXL_CMPLogClose();
INISAFEXSAFE_API int IXL_Change_Password(unsigned char* priv_str , int priv_len, char* pOldPassword, int nOldPasswdlen, char* pNewPassword, int nNewPasswdlen, unsigned char** pNewPrivkey, int* nNewPrivlen);

INISAFEXSAFE_API int IXL_SetCertForUBIKey(unsigned char* cert, int certlen, unsigned char* prikey, int prikeylen);
INISAFEXSAFE_API void IXL_DeleteCertForUBIKey();

/**
 * @brief : IXL_Get_Issue_Certificate_PKCS10[ PKCS10 인증서 발급 전문 가져오기 ]
 * @param : [IN] int nStoreType				[ 발급된 인증서가 저장된 저장 매체 Type ]
 * @param : [IN] unsigned char* pDriveName	[ 드라이브명 , ('C:' 형식 ) ]
 * @param : [IN] int nDriveNamelen			[ 드라이브명 길이 ]
 * @param : [IN] unsigned char* pPIN		[ PIN ]
 * @param : [IN] int nPINlen				[ PIN 길이 ]
 * @param : [IN] unsigned char* pCAName		[ 발급을 요청할 CA 명칭 ]
 * @param : [IN] int nCANamelen				[ 발급을 요청할 CA 명칭 길이 ]
 * @param : [IN] unsigned char* pDn			[ DN ]
 *											사설일 경우 : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d&CANAME=%s&CAPATH=%s
 *											공인일 경우 : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d
 * @param : [IN] int nDnlen					[ DN 길이 ]
 * @param : [IN] unsigned char* pPassword	[ 비밀 번호 ]
 * @param : [IN] int nPasswordlen			[ 비밀 번호 길이 ]
 * @param : [OUT]unsigned char** pOutData	[ PKCS10 전문 ]
 * @param : [OUT]int* nOutDatalen			[ PKCS10 전문 길이 ]
 */
INISAFEXSAFE_API int IXL_Get_Issue_Certificate_PKCS10_VP(char* pDn, int nDnlen, unsigned char* pPassword, int nPasswordlen,
														  unsigned char** pOutData, int *nOutDatalen, unsigned char** pPrikeyOutData, int* nPriKeylen);
INISAFEXSAFE_API int IXL_GetX509Value(unsigned char* pCert, int nCertlen, _certInfo_ext** info);

INISAFEXSAFE_API int IXL_ReadData (char* path, int encodeflag, bool ispem, unsigned char** outdata, int* nOutlen);

INISAFEXSAFE_API int IXL_CertHashName (unsigned char* pCert, int nCertLen, char* hash ,unsigned char** outdata, int* nOutlen);

INISAFEXSAFE_API int IXL_IssueCertToUBIKey(char* pwd, char* CAName, char* pdn, char* hash, char* keylen, unsigned char** pb64cert, int* certlen, unsigned char** pb64prikey, int* prikeylen);

INISAFEXSAFE_API int IXL_VerifyCerts(IXLCertinfolist** pRoot_list);

INISAFEXSAFE_API int IXL_VerifyCert(unsigned char* cacert, int cacertlen, unsigned char* usercert, int usercertlen);

INISAFEXSAFE_API void IXL_DeleteCaCertArray();

INISAFEXSAFE_API int IXL_AppendCaCert(unsigned char* cacert, int cacertlen);

INISAFEXSAFE_API int IXL_InitCaCertArray();

INISAFEXSAFE_API int IXL_SymEncIniData(char* domain,unsigned char *indata, int inlen, char *ciphername, unsigned char **outdata, int *outlen);
INISAFEXSAFE_API int IXL_SymDecIniData(char* domain, unsigned char *indata, int inlen, char *ciphername, unsigned char **outdata, int *outlen);

INISAFEXSAFE_API unsigned char* IXL_GetSubjectDnFromIssuedCert();
INISAFEXSAFE_API int IXL_GetVID(char* path, char *password, unsigned char **rand, int *rand_len);

/* random add */
INISAFEXSAFE_API int IXL_GetPRNG_Random(unsigned char** rand, int rand_len);

INISAFEXSAFE_API int IXL_GetFilterInfoFromCert(unsigned char* cert, int nCertlen, char** issuer, char** subjectdn, char** serial);
#endif



enum STORETYPE
{
		HDD, FDD, SCARD, USBT, CA, ROOT, MEMORY, ICCARD, PHONE, PUBROOT, PRIVROOT, IPHONE_KEYCHAIN, HSM
};

#define STORAGE_HDD		0x01
#define STORAGE_FDD		0x02
#define STORAGE_SCARD	0x04
#define STORAGE_USBT	0x08


INISAFEXSAFE_API void IXL_Init(void);
INISAFEXSAFE_API void IXL_Cleanup(void);
INISAFEXSAFE_API int IXL_LogInit(char *path, char *name, int level);
INISAFEXSAFE_API void IXL_LogClose(void);

INISAFEXSAFE_API int IXL_Get_Server_Time(char *pTm, time_t *PT); // add by junsoon.ahn 2012.10.22
INISAFEXSAFE_API int IXL_CountCerts(int storetype,const char *pin, char *path);
INISAFEXSAFE_API int IXL_GetAllCertHeader(int storetype, const char *pin, const char *path, char **outlist);
INISAFEXSAFE_API int IXL_GetAllCertHeaderFilter(int storetype, const char *pin, const char *path, char *filterStr, char **outlist);
INISAFEXSAFE_API int IXL_FetchCertList(int storetype, const char *pin, const char *mountpath);
INISAFEXSAFE_API int IXL_FetchCertListFilter(int storetype, const char *pin, const char *mountpath, char *filterStr);
INISAFEXSAFE_API int IXL_GetCertPkeyPath(int idx, char *certpath, char *pkeypath);
INISAFEXSAFE_API int IXL_GetCertPkey(int idx, unsigned char **cert, int *certlen, unsigned char **pkey, int *pkeylen);
INISAFEXSAFE_API int IXL_GetsubjectDN(int idx, char **subjectdn);
INISAFEXSAFE_API void IXL_Free (void *p , int len);

    
/** byoungkuk.kim modify 2014.02.14 start */
#ifndef _IPHONE
INISAFEXSAFE_API int IXL_CheckPOP(int idx, char *password, int passwordlen);
INISAFEXSAFE_API int IXL_ChangePasswd(int idx, const char* oldPasswd, const char* newPasswd);
INISAFEXSAFE_API int IXL_CheckVID(int idx, char *password, char *ssn);
INISAFEXSAFE_API int IXL_GetPK8Random(int idx, char *password, unsigned char **rand, int *rand_len);
/**
 * @brief : IXL_Get_Issue_Certificate_PKCS10[ PKCS10 인증서 발급 전문 가져오기 ]
 * @param : [IN] int nStoreType				[ 발급된 인증서가 저장된 저장 매체 Type ]
 * @param : [IN] unsigned char* pDriveName	[ 드라이브명 , ('C:' 형식 ) ]
 * @param : [IN] int nDriveNamelen			[ 드라이브명 길이 ]
 * @param : [IN] unsigned char* pPIN		[ PIN ]
 * @param : [IN] int nPINlen				[ PIN 길이 ]
 * @param : [IN] unsigned char* pCAName		[ 발급을 요청할 CA 명칭 ]
 * @param : [IN] int nCANamelen				[ 발급을 요청할 CA 명칭 길이 ]
 * @param : [IN] unsigned char* pDn			[ DN ]
 *											사설일 경우 : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d&CANAME=%s&CAPATH=%s
 *											공인일 경우 : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d
 * @param : [IN] int nDnlen					[ DN 길이 ]
 * @param : [IN] unsigned char* pPassword	[ 비밀 번호 ]
 * @param : [IN] int nPasswordlen			[ 비밀 번호 길이 ]
 * @param : [OUT]unsigned char** pOutData	[ PKCS10 전문 ]
 * @param : [OUT]int* nOutDatalen			[ PKCS10 전문 길이 ]
 */
    
#ifndef _MACOS
INISAFEXSAFE_API int IXL_Get_Issue_Certificate_PKCS10 (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,
                                                       char* pDn, int nDnlen, unsigned char* pPassword, int nPasswordlen,unsigned char** pOutData, int *nOutDatalen);
#else
INISAFEXSAFE_API int IXL_Get_Issue_Certificate_PKCS10_ex (int nStoreType, char *pDriveName, int nDriveNamelen, unsigned char *pPin, int nPinlen,  char *pCAName,int nCANamelen,
                                                              char *pDn, int nDnlen, unsigned char *pPassword, int nPasswordlen,unsigned char **pOutData, int *nOutDatalen, unsigned char **priv_der, int *priv_derlen);
#endif
    
INISAFEXSAFE_API int IXL_Get_Issue_Certificate_PKCS10_new (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,
                                                       char* pDn, int nDnlen, int bit, unsigned char* pPassword, int nPasswordlen,unsigned char** pOutData, int *nOutDatalen);

/**
 * @brief :	IXL_Store_PCertAndPPriKey
 * @param : [IN] unsigned char *PrivKey	[ PKCS#8 DER
 * @param : [IN] int PrivKeyLen
 * @param : [IN] char* passwd
 * @remark
 *  add by hspark . 2013.03.11
 *  for use only Linux , OS/X
 */
INISAFEXSAFE_API int IXL_Store_PCertAndPPriKey(int nDestStoreType,char* pSaveDrive,char *certPEM,unsigned char *PrivKey,int PrivKeyLen,char* passwd);
    
/**
 * @brief   : KeyCain으로부터 PFX(PKCS#12) 데이터로 가져오기(인증서내보내기).
 * @param	: [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param	: [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 * @param	: [OUT] unsigned char** pP12		[ P12 데이터 ]
 * @param	: [OUT] int *nP12len				[ P12 데이터 길이 ]
 */
INISAFEXSAFE_API int IXL_Get_PFXBuf_KeyChain (int idx, unsigned char* pPassword, int nPasswordlen, unsigned char **pP12, int *nP12len);
/**
 * @brief   : PFX(PKCS#12) 데이터로 부터 KeyChain으로 가져오기(인증서저장).
 * @param	: [IN] unsigned char* pP12			[ P12 데이터 ]
 * @param	: [IN] int nP12len					[ P12 데이터 길이 ]
 * @param	: [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param	: [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 */
INISAFEXSAFE_API int IXL_Get_KeyChain_PFXBuf (unsigned char* pP12, int nP12len, unsigned char* pPassword, int nPasswordlen);
//IXL_PKCS7_Cert_With_Random
INISAFEXSAFE_API int IXL_MakeINIPlugindata_phone(char *sid, int vf, int idx,
                                                                               unsigned char* pPassword, int nPasswordlen,
                                                                               char *vd_data, int vd_data_len,
                                                                               unsigned char *indata, int indata_len,
                                                                               char **outdata, int *outdata_len);
INISAFEXSAFE_API int IXL_MakeINIPluginData_1(char *sid, int vf, int idx,
                                                                           unsigned char* pPassword, int nPasswordlen,
                                                                           char *vd_data, int vd_data_len,
                                                                           unsigned char *indata, int indata_len,
                                                                           char **outdata, int *outdata_len);
INISAFEXSAFE_API int IXL_Check_MinLength(const unsigned char* password, const int passlen, int minlength);
INISAFEXSAFE_API int IXL_Check_MaxLength(const unsigned char* password, const int passlen, int maxlength);
INISAFEXSAFE_API int IXL_Check_Continous_Letter(const unsigned char* password, const int passlen, int checklength);
INISAFEXSAFE_API int IXL_Check_Continous_Reverse_Digit(const unsigned char* password, const int passlen, int checklength);
INISAFEXSAFE_API int IXL_Check_Repeated_Letter(const unsigned char* password, const int passlen, int repeatcnt);
INISAFEXSAFE_API int IXL_Check_Type_Of_Character(const unsigned char* password, const int passlen);
/**
 * @brief : IXL_Issue_Certificate_Reduction		[ 인증서 발급. (Parameter 축소) ]
 * @param : [IN] int nStoreType					[ 발급된 인증서가 저장된 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT
 * @param : [IN] unsigned char* pDriveName		[ 드라이브명 , ('C:' 형식 ) ]
 * @param : [IN] int nDriveNamelen				[ 드라이브명 길이 ]
 * @param : [IN] unsigned char* pPIN			[ PIN ]
 * @param : [IN] int nPINlen					[ PIN 길이 ]
 * @param : [IN] unsigned char* pCAName			[ 발급을 요청할 CA 명칭 ]
 * @param : [IN] int nCANamelen					[ 발급을 요청할 CA 명칭 길이 ]
 * @param : [IN] unsigned char* pDn				[ DN ]
 *											사설일 경우 : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d&CANAME=%s&CAPATH=%s
 *											공인일 경우 : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d
 * @param : [IN] int nDnlen						[ DN 길이 ]
 * @param : [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param : [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 * @param : [IN] unsigned char* pHashAlg		[ 해쉬 알고리즘 ]
 * @param : [IN] int nReflen					[ 해쉬 알고리즘 길이 ]
 * @param : [IN] unsigned char* pKeyBit			[ Key 길이 ]
 * @param : [IN] int nKeyBitlen					[ Key 길이 ]
 */
INISAFEXSAFE_API int IXL_Issue_Certificate_Reduction (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,
                                                                                    char* pDn, int nDnlen, unsigned char* pPassword, int nPasswordlen, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);
/**
 * @brief : IXL_RSA_Private_Sign		[ 개인키를 이용하여 서명 ]
 * @param : [IN] unsigned char* key		[ private Key ]
 * @param : [IN] int keyl				[ private Key length ]
 * @param : [IN] int pad_mode			[ Padding mode ]
 *										ICL_NO_PAD				0x00
 *										ICL_RSASSA_PKCS1_15		0x01 RSA signature PKCS1 v1.5 ENCODE
 *										ICL_RSASSA_PSS			0x02 RSA signature PSS ENCODE
 * @param : [IN] char encode_flag		[ 출력 데이터의 Encoding/Decoding 설정 ]
 *										ICL_NO_ENCODE		0x10	No encoding flag
 *										ICL_B64_ENCODE		0x00	Base64 encoding flag
 *										ICL_B64_LF_ENCODE	0x01	Base64 encoding with 'insert linefeed' flag
 * @param : [IN]char* hash_alg			[ Hash Algorithm Name (ex) "SHA256" , ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2") ]
 * @param : [IN] unsigned char* indata	[ plain text ]
 * @param : [IN] int indatal			[ plain text Length  ]
 * @param : [OUT]unsgined char** outdata[ Sign Data ]
 * @param : [OUT]int* outdatal			[ Sign Data Length ]
 */
INISAFEXSAFE_API int IXL_RSA_Private_Sign (unsigned char* key, int keyl , unsigned char* pwd, int pwdl, char pad_mode,char encode_flag,
                                                                         char* hash_alg,unsigned char* indata, int indatal , unsigned char** outdata,int* outdatal );
/**** inicis ****/
INISAFEXSAFE_API int IXL_RSASignWithBase64(char *privkey, char *privkey_pass,char *mdname, unsigned char *in,int in_len, unsigned char** sig_data, int *sig_data_len);

/**
 * @brief : IXL_RSA_Private_Crypto		[ 개인키를 이용하여 RSA 암호화 / 복호화 ]
 * @param : [IN] encrypt_flag			[ 1: 암호화 , 1이외일 경우 복호화  ]
 * @param : [IN] unsigned char* key		[ private Key ]
 * @param : [IN] int keyl				[ private key length ]
 * @param : [IN] unsigned char* pwd		[ private key password ]
 * @param : [IN] int pwdl				[ private key password length ]
 * @param : [IN] int pad_mode			[ Padding mode ]
 *										ICL_RSAES_PKCS1_15			0x20 RSA encryption PKCS1 v1.5 ENCODE
 *										ICL_RSAES_OAEP_20			0x08 RSA encryption OAEP v2.0 ENCODE
 *										ICL_RSAES_OAEP_21			0x10 RSA encryption OAEP v2.1 ENCODE
 * @param : [IN] char encode_flag		[ 출력 데이터의 Encoding/Decoding 설정 ]
 *										ICL_NO_ENCODE		0x10	No encoding flag
 *										ICL_B64_ENCODE		0x00	Base64 encoding flag
 *										ICL_B64_LF_ENCODE	0x01	Base64 encoding with 'insert linefeed' flag
 * @param : [IN]char* hash_alg			[ Hash Algorithm Name (ex) "SHA256" , (SHA1 | SHA256 | SHA512 | HAS160) ]
 * @param : [IN] unsigned char* indata	[ 입력 데이터 ]
 * @param : [IN] int indatal			[ 입력 데이터 길이 ]
 * @param : [OUT]unsgined char** outdata[ 암호화 / 복호화된 데이터 ]
 * @param : [OUT]int* outdatal			[ 암호화 / 복호화된 데이터 길이 ]
 */
INISAFEXSAFE_API int IXL_RSA_Private_Crypto (int encrypt_flag,unsigned char* key, int keyl ,unsigned char* pwd,int pwdl , char pad_mode,
                                                                           char encode_flag,char* hash_alg,unsigned char* indata,int indatal, unsigned char** outdata,int* outdatal);



#endif
/** byoungkuk.kim modify 2014.02.14 end */

    

    
    
/** byoungkuk.kim add 2014.02.14 start */
#ifdef _IPHONE
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_CheckPOP(int idx, char *password, int passwordlen);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_CheckPOP(int idx, NSData *password);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_ChangePasswd(int idx, const char* oldPasswd, const char* newPasswd);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_ChangePasswd(int idx, NSData* oldPasswd, NSData* newPasswd);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_CheckVID(int idx, char *password, char *ssn);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_CheckVID(int idx, NSData *password, NSData *ssn);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_CheckVID(int idx, NSData *password, char *ssn, NSData *ssnEnc);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_GetPK8Random(int idx, char *password, unsigned char **rand, int *rand_len);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_GetPK8Random(int idx, NSData *password, unsigned char **rand, int *rand_len);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Get_Issue_Certificate_PKCS10 (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,
                                                                                         char* pDn, int nDnlen, unsigned char* pPassword, int nPasswordlen,unsigned char** pOutData, int *nOutDatalen);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Get_Issue_Certificate_PKCS10 (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,
                                                                                         char* pDn, int nDnlen, NSData* pPassword,unsigned char** pOutData, int *nOutDatalen);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Get_Issue_Certificate_PKCS10_new (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,
                                                                                         char* pDn, int nDnlen, int bit, unsigned char* pPassword, int nPasswordlen,unsigned char** pOutData, int *nOutDatalen);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Get_Issue_Certificate_PKCS10_new (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,
                                                                                         char* pDn, int nDnlen, int bit, NSData* pPassword, unsigned char** pOutData, int *nOutDatalen);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Get_PFXBuf_KeyChain (int idx, unsigned char* pPassword, int nPasswordlen, unsigned char **pP12, int *nP12len);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Get_PFXBuf_KeyChain (int idx, NSData* pPassword, unsigned char **pP12, int *nP12len);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Get_KeyChain_PFXBuf (unsigned char* pP12, int nP12len, unsigned char* pPassword, int nPasswordlen);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Get_KeyChain_PFXBuf (unsigned char* pP12, int nP12len, NSData* pPassword);


// add by junsoon.ahn 2012.10.22
/**
 * @brief : IXL_PKCS7_Cert_With_Random           [ PKCS#7 Sign , Cert Advanced ]
 * @param : [IN] int idx                         [ certificate index ]
 * @param : [IN] int nWithRandomFlag             [ OutPut Data의 WithRandom 설정 ]
 *              (0) WithRandom 안함,   (1) WithRandom
 * @param : [IN] struct tm *recv_time            [ received time ]
 * @param : [IN] unsigned char* pwd              [ password of private key ]
 * @param : [IN] int pwdl                        [ length of password ]
 * @param : [IN] unsigned char* org_data         [ original data ]
 * @param : [IN] int org_datal                   [ original data length ]
 * @param : [IN] int encoding flag               [ encoding flag ]
 * @param : [OUT]unsigned char** outcert         [ DER format cert, Base64 Encoding ]
 * @param : [OUT]int* outcertl                   [ DER format cert Length ]
 * @param : [OUT]unsigned char** outdata         [ PKCS#7 data ]
 * @param : [OUT]int* outdatal                   [ PKCS#7 data length ]
 * @param : [OUT]unsigned char** random          [ private key random data ]
 * @param : [OUT]int* outdatal                   [ random data length ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_PKCS7_Cert_With_Random (int idx, int nWithRandomFlag, struct tm *recv_time, unsigned char* pwd,int pwdl, unsigned char* org_data, int org_datal,int encodingflag, unsigned char** outcert , int* outcertl, unsigned char** outdata, int* outdatal);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_PKCS7_Cert_With_Random (int idx, int nWithRandomFlag, struct tm *recv_time, NSData* pwd, unsigned char* org_data, int org_datal,int encodingflag, unsigned char** outcert , int* outcertl, unsigned char** outdata, int* outdatal);
    
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_PKCS7_Cert_PKey_With_Random (unsigned char *cert, int certl, unsigned char *priv, int privl, int nWithRandomFlag, struct tm *recv_time, unsigned char* pwd,int pwdl, unsigned char* org_data, int org_datal,int encodingflag, unsigned char** outdata, int* outdatal);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_PKCS7_Cert_PKey_With_Random (unsigned char *cert, int certl, unsigned char *priv, int privl, int nWithRandomFlag, struct tm *recv_time, NSData* pwd, unsigned char* org_data, int org_datal,int encodingflag, unsigned char** outdata, int* outdatal);
    
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_MakeINIPlugindata_phone(char *sid, int vf, int idx,
                                                                               unsigned char* pPassword, int nPasswordlen,
                                                                               char *vd_data, int vd_data_len,
                                                                               unsigned char *indata, int indata_len,
                                                                               char **outdata, int *outdata_len);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_MakeINIPlugindata_phone(char *sid, int vf, int idx,
                                                                               NSData* pPassword,
                                                                               char *vd_data, int vd_data_len,
                                                                               unsigned char *indata, int indata_len,
                                                                               char **outdata, int *outdata_len);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_MakeINIPluginData_1(char *sid, int vf, int idx,
                                                                               unsigned char* pPassword, int nPasswordlen,
                                                                               char *vd_data, int vd_data_len,
                                                                               unsigned char *indata, int indata_len,
                                                                               char **outdata, int *outdata_len);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_MakeINIPluginData_1(char *sid, int vf, int idx,
                                                                               NSData* pPassword,
                                                                               char *vd_data, int vd_data_len,
                                                                               unsigned char *indata, int indata_len,
                                                                               char **outdata, int *outdata_len);

/**
 * @brief : IXL_Check_MinLength                 [ 문자 최소 길이 체크 ]
 * @param : [IN] const unsigned char* password	[ 비밀번호 ]
 * @param : [IN] const int passlen              [ 비밀번호 길이 ]
 * @param : [IN] int minlength                  [ 비밀번호 제한 최소 길이 ]
 * return : 정합할 경우 : IXL_OK , 정합하지 않을 경우; IXL_NOK
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_MinLength(const unsigned char* password, const int passlen, int minlength);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_MinLength(NSData* password, int minlength);
/**
 * @brief : IXL_Check_MaxLength                 [ 문자 최대 길이 체크 ]
 * @param : [IN] const unsigned char* password	[ 비밀번호 ]
 * @param : [IN] const int passlen              [ 비밀번호 길이 ]
 * @param : [IN] int maxlength                  [ 비밀번호 제한 최대 길이 ]
 * return : 정합할 경우 : IXL_OK , 정합하지 않을 경우; IXL_NOK
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_MaxLength(const unsigned char* password, const int passlen, int maxlength);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_MaxLength(NSData* password, int maxlength);
/**
 * @brief : IXL_Check_Continous_Letter			[ 연속된 문자 체크 (영문자, 숫자)]
 * @param : [IN] const unsigned char* password	[ 비밀번호 ]
 * @param : [IN] const int passlen              [ 비밀번호 길이 ]
 * @param : [IN] int checklength				[ 비밀번호 연속된 문자 제한 길이 ]
 * return : 정합할 경우 : IXL_OK , 정합하지 않을 경우; IXL_NOK
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Continous_Letter(const unsigned char* password, const int passlen, int checklength);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Continous_Letter(NSData* password, int checklength);
/**
 * @brief : IXL_Check_Continous_Reverse_Digit	[ 역순으로 연속된 숫자 체크 ]
 * @param : [IN] const unsigned char* password	[ 비밀번호 ]
 * @param : [IN] const int passlen              [ 비밀번호 길이 ]
 * @param : [IN] int checklength				[ 비밀번호 연속된 문자 제한 길이 ]
 * return : 정합할 경우 : IXL_OK , 정합하지 않을 경우; IXL_NOK
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Continous_Reverse_Digit(const unsigned char* password, const int passlen, int checklength);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Continous_Reverse_Digit(NSData* password, int checklength);
/**
 * @brief : IXL_Check_Repeated_Letter           [ 반복 문자 문자 체크 ]
 * @param : [IN] const unsigned char* password	[ 비밀번호 ]
 * @param : [IN] const int passlen              [ 비밀번호 길이 ]
 * @param : [IN] int repeatcnt                  [ 비밀번호 동일한 문자 제한 길이 ]
 * return : 정합할 경우 : IXL_OK , 정합하지 않을 경우; IXL_NOK
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Repeated_Letter(const unsigned char* password, const int passlen, int repeatcnt);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Repeated_Letter(NSData* password, int repeatcnt);
/**
 * @brief : IXL_Check_Type_Of_Character         [ 영문숫자특수문자 혼합 체크 ]
 * @param : [IN] const unsigned char* password	[ 비밀번호 ]
 * @param : [IN] const int passlen              [ 비밀번호 길이 ]
 * return : 정합할 경우 : IXL_OK , 정합하지 않을 경우; IXL_NOK
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Type_Of_Character(const unsigned char* password, const int passlen);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Type_Of_Character(NSData* password);

INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_UsedCharTypeCount(const unsigned char* password, const int passlen, int typeCount, NSString *specialCharList);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_UsedCharTypeCount(NSData* password, int typeCount, NSString *specialCharList);
    
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_AlphabetType(const unsigned char* password, const int passlen);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_AlphabetType(NSData* password);
    
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_NumberType(const unsigned char* password, const int passlen);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_NumberType(NSData* password);

INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_SpecialCharType(const unsigned char* password, const int passlen, NSString *specialCharList);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_SpecialCharType(NSData* password, NSString *specialCharList);
    
/**
 * @brief : IXL_Keychain_Update_Cert			[ 인증서 갱신(iOS용 키체인 저장).]
 * @param : [IN] int idx						[ 인증서 리스트 index ]
 * @param : [IN] unsigned char* pCAName			[ 갱신을 요청할 CA 명칭 ]
 * @param : [IN] int nCANamelen					[ 갱신을 요청할 CA 명칭 길이 ]
 * @param : [IN] unsigned char* pDn				[ DN ]
 * @param : [IN] int nDnlen						[ Dn 길이 ]
 * @param : [IN] unsigned char* pOldPassword	[ 이전 비밀 번호 ]
 * @param : [IN] int nOldPasswordlen			[ 이전 비밀 번호 길이 ]
 * @param : [IN] unsigned char* pNewPassword	[ 새로운 비밀 번호 ]
 * @param : [IN] int nNewPasswordlen			[ 새로운 비밀 번호 길이 ]
 * @param : [IN] unsigned char* pHashAlg		[ 해쉬 알고리즘 ]
 * @param : [IN] int nReflen					[ 해쉬 알고리즘 길이 ]
 * @param : [IN] unsigned char* pKeyBit			[ Key 길이 ]
 * @param : [IN] int nKeyBitlen					[ Key 길이 ]
 */
//INISAFEXSAFE_API int IXL_Keychain_Update_Cert (int idx, char* pCAName, int nCANamelen,  char* pDN, int nDnlen, unsigned char* pOldPassword, int nOldPasswordlen, unsigned char* pNewPassword,
//											   int nNewPasswordlen, char* pHashalg, int nHashAlglen, unsigned char* pKeyBit, int nKeyBitlen);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Keychain_Update_Cert (int idx, char* pCAName,  char* pDN , unsigned char* pOldPassword, unsigned char* pNewPassword, char* pHashalg, unsigned char* pKeyBit);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Keychain_Update_Cert (int idx, char* pCAName,  char* pDN , NSData* pOldPassword, NSData* pNewPassword, char* pHashalg, unsigned char* pKeyBit);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Issue_Certificate_Reduction (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,
                                                                                    char* pDn, int nDnlen, unsigned char* pPassword, int nPasswordlen, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Issue_Certificate_Reduction (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,
                                                                                    char* pDn, int nDnlen, NSData* pPassword, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_RSA_Private_Sign (unsigned char* key, int keyl , unsigned char* pwd, int pwdl, char pad_mode,char encode_flag,
                                                                         char* hash_alg,unsigned char* indata, int indatal , unsigned char** outdata,int* outdatal );
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_RSA_Private_Sign (unsigned char* key, int keyl , NSData* pwd, char pad_mode,char encode_flag,
                                                                         char* hash_alg,unsigned char* indata, int indatal , unsigned char** outdata,int* outdatal );
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_RSASignWithBase64(char *privkey, char *privkey_pass,char *mdname, unsigned char *in,int in_len, unsigned char** sig_data, int *sig_data_len);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_RSASignWithBase64(char *privkey, NSData *privkey_pass,char *mdname, unsigned char *in,int in_len, unsigned char** sig_data, int *sig_data_len);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_RSA_Private_Crypto (int encrypt_flag,unsigned char* key, int keyl ,unsigned char* pwd,int pwdl , char pad_mode,
                                                                           char encode_flag,char* hash_alg,unsigned char* indata,int indatal, unsigned char** outdata,int* outdatal);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_RSA_Private_Crypto (int encrypt_flag,unsigned char* key, int keyl ,NSData* pwd, char pad_mode,
                                                                                                                                     char encode_flag,char* hash_alg,unsigned char* indata,int indatal, unsigned char** outdata,int* outdatal);
 
INISAFEXSAFE_API void IXL_nFilterKeyCleanup(void);
INISAFEXSAFE_API int IXL_nFilterKeyCheck(void);
INISAFEXSAFE_API int IXL_SetNFilterPublicKey(NSString *publicKey);
#endif
/** byoungkuk.kim add 2014.02.14 end */

                                                                           
                                                                           
INISAFEXSAFE_API int IXL_DeleteCert(int idx);

#ifdef _IPHONE    
INISAFEXSAFE_API int IXL_SaveCertPkeys(int storetype, const char *pin, const char *path, unsigned char *cert, int certlen, unsigned char *key, int keylen, unsigned char *kmcert, int kmcertlen, unsigned char *kmkey, int kmkeylen);
INISAFEXSAFE_API int IXL_SaveCACerts(int nFlag, char* caCerts, char** caCertificateKeyList);
INISAFEXSAFE_API int IXL_GetCACertKeyList(char** caCertificateKeyList);
#endif
INISAFEXSAFE_API int IXL_SaveCertPkey(int storetype, const char *pin, const char *path, unsigned char *cert, int certlen, unsigned char *key, int keylen);


INISAFEXSAFE_API void IXL_SetKeyChainName(char *strName);
INISAFEXSAFE_API int IXL_GetPEMCert (int idx, int nFlag, unsigned char** pPemCert, int* nPemCertlen);


#ifdef _IPHONE
INISAFEXSAFE_API int IXL_DecryptAndSaveWithAuthcode(char *encryptedMsg, int encryptedMsglen, char *authCode);
INISAFEXSAFE_API int IXL_EncryptFromCertWithAuthCode(int idx, char *authCode, char **pKeyAndCert_base64, int *nKeyAndCert_base64len);
INISAFEXSAFE_API int IXL_MigrateNewXsafeToMobilianSFilterKeychain(void);
INISAFEXSAFE_API int IXL_MigrateMobilianSFilterKeychain(void);
INISAFEXSAFE_API int IXL_MigrationOldXSafeKeychain(void);
INISAFEXSAFE_API int IXL_GetAllKeychainCertHeaderFilterforCaAndOID(char *caNames, char *certificateOIDs, char **outlist);
INISAFEXSAFE_API int IXL_GetAllKeychainCertHeaderFilterforCaCertsAndOIDs(char *caCertificateLists, char *certificateOIDs, char **outlist);
INISAFEXSAFE_API void IXL_SetKeyChainCertificateType(int certificateType);
INISAFEXSAFE_API int IXL_SetKeyChainAccessGroup(char *groupAccess, int *keychainStatus);
INISAFEXSAFE_API int IXL_FetchCertListFilterOnKeychain(char *filterStr); /*use for iOS keychain*/
INISAFEXSAFE_API int IXL_FetchCertListOIDFilterOnKeychain(char *caNames, char *certificateOIDs); /*use for iOS keychain*/
INISAFEXSAFE_API int IXL_FetchCertListCACertsAndOIDsFilterOnKeychain(char *caCertificateLists, char *certificateOIDs);
INISAFEXSAFE_API int IXL_PurgeKeychainGroup(char *groupAccess, int *keychainStatus); /*initialize all keychain*/
#endif
    
/*
 기존 iPhone 가져오기 호환을 위해 함수 추가. 
    encryptedMsg : 서버로 부터 전송된 암호화된 개인키+인증서
    encryptedMsglen : encryptedMsg 의 길이
    regnum : 주민등록번호 13자리 
    verifyid : 인증번호 16자리
 */
#if defined(_INI_BADA) 
INISAFEXSAFE_API int IXL_DecryptAndSave(unsigned char *encryptedMsg, int encryptedMsglen, char *regnum, char *verifyid, const char* path);
#elif defined (_WIN8STORE) 
INISAFEXSAFE_API int IXL_DecryptAndSave(unsigned char *encryptedMsg, int encryptedMsglen, char *regnum, char *verifyid, char* pwd);
#else
INISAFEXSAFE_API int IXL_DecryptAndSave(unsigned char *encryptedMsg, int encryptedMsglen, char *regnum, char *verifyid);				
#endif

    
    
/**
 * @brief : IXL_ServerCert_Verify_Validity	[ SCert 유효성 Check ]
 * @param : [IN] unsigned char* scert		[ scert ]
 * @param : [IN] int scertl					[ scert length ]
 * @return
 *			0 : success , -1 : fail
 */
INISAFEXSAFE_API int IXL_ServerCert_Verify_Validity (unsigned char* scert, int scertl);

    
    
/* iniplugindata for iphone */
INISAFEXSAFE_API void IXL_ClearINIPluginDataProperty(char *sid);
INISAFEXSAFE_API int IXL_GetINIPluginDataProperty(char *sid, unsigned char **scert, int *scert_len, 
									 char **sym, char **kx, char **kxh, char **sg, char **sgh, 
									 unsigned char **sk, int *sk_len, unsigned char **iv, int *iv_len);
INISAFEXSAFE_API int IXL_SetINIPluginDataProperty(char *sid, unsigned char *scert, int scert_len, char *sym, char *kx, char *kxh, char *sg, char *sgh);
//INISAFEXSAFE_API int IXL_MakeINIPlugindata_phone(char *sid, int vf, int idx, unsigned char* pPassword, int nPasswordlen,
//												 char *vd_data, int vd_data_len, unsigned char *indata, int indata_len,
//												 char **outdata, int *outdata_len);



INISAFEXSAFE_API int IXL_MakeINIPluginData_0(char *sid, int vf, unsigned char *indata, int indata_len, char **outata, int *outdata_len);

INISAFEXSAFE_API int IXL_IPDecrypt(char *sid, unsigned char *indata, int indata_len, unsigned char **outdata, int *outdata_len);
	
#ifndef NO_SIGN
INISAFEXSAFE_API int IXL_EnvelopedEncBASE64WithSkeyIV(char *skid, char *certstr,int certlen, char* ciphername, unsigned char *indata, int indatalen, unsigned char **outdata, int *outdatalen);
#endif


INISAFEXSAFE_API int IXL_SkIdInfoCntInc();
INISAFEXSAFE_API int IXL_InitSkIdArray(unsigned char *certstr, int certlen , unsigned char *sessionkey, unsigned char *iv, unsigned char *outskid);
INISAFEXSAFE_API int IXL_AddSkeyIV(unsigned char *certstr, int certlen, unsigned char *skey, unsigned char *iv, unsigned char *outskid);
INISAFEXSAFE_API int IXL_GetSkeyIV(char *skid, unsigned char *outskey, unsigned char *outiv);
INISAFEXSAFE_API int IXL_EnvelopedEncBASE64WithSKeyIV(char *skid, char *certstr,int certlen, char* ciphername, unsigned char *indata, int indatalen, unsigned char **outdata, int *outdatalen);
#ifndef NO_SIGN
INISAFEXSAFE_API int IXL_PKCS7EnvelopedDecWithSKeyIV_path(char *certpath, char *pkeypath, char *pkeypasswd ,char *p7data,int p7datalen, char** out, int* outl ,unsigned char *outskey, unsigned char *outiv);
#endif
INISAFEXSAFE_API int IXL_SymEncMatchSkeyIV(char *skid, unsigned char *indata, int inlen, char *ciphername, unsigned char **outdata, int *outlen);
INISAFEXSAFE_API int IXL_SymDecMatchSkeyIV(char *skid, unsigned char *indata, int inlen, char *ciphername, unsigned char **outdata, int *outlen);

INISAFEXSAFE_API void IXL_SkIdArrayCleanup(void);




/**** inicis ****/
INISAFEXSAFE_API void IXL_GenSessionKeyWithBase64(char **b64skeyout);
INISAFEXSAFE_API int IXL_Base64EncodeMalloc(char *indata, int inlen, char **outdata);
INISAFEXSAFE_API int IXL_Base64DecodeMalloc(char *indata, int inlen, unsigned char **outdata);
INISAFEXSAFE_API int IXL_SymEncryptWithBase64(char **out, char *data, char* ciphername, unsigned char* key, unsigned char* iv);
INISAFEXSAFE_API int IXL_SymEncryptWithBase64_B64Skey(char **out, char *b64data, char* ciphername, unsigned char* b64key, unsigned char* iv);
INISAFEXSAFE_API int IXL_RSAPublicEncryptDataWithBase64(char *in, int inl, char **out, char *pubkey, int publen);

INISAFEXSAFE_API char *IXL_GetRVfromPrivKeyWithBase64(char* privkeypath, char* privkeypass);
INISAFEXSAFE_API char *IXL_URLEncode(char *str);
INISAFEXSAFE_API void IXL_URLDecode(char *str);
INISAFEXSAFE_API int IXL_Base64EncodeNoline(unsigned char *src, int srcl, char *dest, int destl);
INISAFEXSAFE_API int IXL_Base64DecodeNoline(char *src, int srcl,unsigned char *dest, int destl);

INISAFEXSAFE_API char *IXL_Version();
INISAFEXSAFE_API char *IXL_Get_Crypto_Version();
INISAFEXSAFE_API char *IXL_Get_PKI_Version();
INISAFEXSAFE_API char *IXL_Get_Core_Version();
INISAFEXSAFE_API char *IXL_Get_CMP_Version();
INISAFEXSAFE_API int IXL_GetLastError();
INISAFEXSAFE_API char *IXL_GetErrorString(int result);
INISAFEXSAFE_API char *IXL_GetCAErrorString(void);
INISAFEXSAFE_API char *IXL_GetCMPErrorString(void);


/* password check add*/

/**
 * @brief   : 바이너리를 이용한 개인키 비밀 번호 검증
 * @param   : [IN] unsigned char* pPrivKey			[ 개인키 데이터 ]
 * @param	: [IN] int nPrivKeyLen					[ 개인키 데이터 길이 ]
 * @param   : [IN] unsigned char* pPassword			[ 인증서 비밀 번호 ]
 * @param	: [IN] int nPassword					[ 인증서 비밀 번호  길이]
  */
INISAFEXSAFE_API int IXL_Priv_PassWord_Check (unsigned char* pPrivKey, int nPrivKeyLen, unsigned char* pPassword , int nPassword);

/**
 * @brief : IXL_Get_Cert_AlgorithmAndHash		[ 인증서의 Hash 및 Algorthm 가져오기 ]
 * @param : [IN] int type						[ kx : 0 , sg : 1 ]
 * @param : [IN] unsigned char* cert			[ 인증서 ]
 * @param : [IN] int certl						[ 인증서 길이 ]
 * @param : [OUT] char** alg					[ Algorithm ]
 * @param : [OUT] char** hash_alg				[ Hash Algorithm ]
 */
int IXL_Get_Cert_AlgorithmAndHash (int type, unsigned char* cert, int certl, char** alg, char** hash_alg);
	
/**
 * @brief :	IXL_Image_Verify_Signed			[ 이미지 서명 검증 ]
 * @param : [IN] char* pDomain				[ 도메인 정보 ]
 * @param : [IN] int nDomainlen				[ 도메인 정보 길이 ]
 * @param : [IN] unsigned char* pURI		[ 이미지 URI , http 만 지원. Base64 encoding 된 데이터 ]
 * @param : [IN] int nURI					[ 이미지 URI 길이 ]
 * @param : [OUT]unsigned char** pOut		[ 이미지 저장 위치 , Base64 encoding ]
 * @param : [OUT]int* nOutlen				[ 이미지 저장 위치 길이 ]
 * @remark
 *  이미지 URI를 수신 받아 이미지 서명 검증을 진행 한다.
 *  이미지 서명 검증이 성공하면, Local 에 이미지 파일을 저장하고 저장 위치를 Return 한다.
 */
INISAFEXSAFE_API int IXL_Image_Verify_Signed (char* pDomain, int nDomainlen,unsigned char* pURI, int nURIlen, unsigned char** pOut,int *nOutlen);

/**
 * @brief :	IXL_Image_Verify			    [ 이미지 서명 검증 ]
 * @param : [IN] unsigned char* pImageData	[ 서명된 이미지 Data ]
 * @param : [IN] int nImageDatalen			[ 서명된 이미지 Data 길이 ]
 * @param : [OUT]unsigned char** pOut		[ 이미지 원본 Data ]
 * @param : [OUT]int* nOutlen				[ 이미지 원본 Data 길이 ]
 * @remark
 *  서명된 이미지 Data를 받아 이미지 서명 검증을 진행 한다.
 *  이미지 서명 검증이 성공하면, 이미지 원본 Data를 Return 한다.
 */
INISAFEXSAFE_API int IXL_Image_Verify (unsigned char* pImageData, int nImageDatalen, unsigned char** pOut,int *nOutlen);


/**
 * @brief :	IXL_Downloaded_Image_Verify		[ 다운로드한 이미지 파일의 서명 검증 ]
 * @param : [IN] char *downloaded_ImagePath	[ 이미지 파일 Path]
 * @remark
 *  add by hspark . 2013.09.13
 *  이미 다운로드 받은 이미지 파일을 이용하여 서명 검증을 한다.
 *	서명 검증에 성공하면 IXL_OK 리턴
 */
INISAFEXSAFE_API int IXL_Downloaded_Image_Verify(char *downloaded_ImagePath);


/**
 * @brief :	IXL_AppSign_Verify		
 * @param : [IN] char *tarGet_fileName		[ 검증 대상 파일]
 * @param : [IN] char *sig_fileName		[ 검증 대상 파일과 짝이 되는 서명 파일]
 * @remark 
 *  add by hspark . 2013.10.08
 *  위변조 방지를 위하여 임의 검증 대상 파일과 그 서명값을 가지는 서명파일을 비교하여 검증을 진행한다.
 *  맥/리눅스에서만 사용한다.
 *	서명 검증에 성공하면 IXL_OK 리턴
 *  for use only Linux , OS/X
 *		
 */
INISAFEXSAFE_API int IXL_AppSign_Verify(char *tarGet_fileName,char *sig_fileName);



/**
 * @param : [IN] unsigned char *PrivKey	[ PKCS#8 DER
 * @param : [IN] int PrivKeyLen			[ 
 * @param : [IN] char* passwd			[ 
 * @remark
 *  add by hspark . 2013.03.11
 
 *  for use only Linux , OS/X
 */
INISAFEXSAFE_API int IXL_Make_Temp_PPriKey(unsigned char *PrivKey,int PrivKeyLen,char* passwd);



/**
 * @brief :	IXL_Make_PCertAndPPriKey
 * @param : [IN] int nDestStoreType		[
 * @param : [IN] char* pSaveDrive		[
 * @param : [IN] char *certPEM			[ PEM X.509 Certificate ]
 * @remark
 
 *  for use only Linux , OS/X
 */
INISAFEXSAFE_API int IXL_Make_PCertAndPPriKey(int nDestStoreType,char* pSaveDrive,char *certPEM);

    
    
/**
 * @brief : IXL_Get_Domain_CertList				[ (도메인) 인증서 목록 가져오기 ]
 * @param : [IN] int storetype					[ 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param : [IN] unsigned char* pDriveName		[ 저장할 드라이브 명 ]
 * @param : [IN] int nDriveNamelen				[ 저장할 드라이브 명 길이 ]
 * @param : [IN] unsigned char* pPin			[ PIN  정보 ]
 * @param : [IN] int nPinlen 					[ PIN 데이터 길이 ]
 * @param : [IN] char* pDomain					[ 도메인 정보 ]
 * @param : [IN] int nDomainlen					[ 도메인 정보 길이 ]
 * @param : [IN] unsigned char* pFilter			[ 필터 정보 ]
 * @param : [IN] int nFilterlen					[ 필터 정보 길이 ]
 * @param : [OUT]unsigned char** pOutData		[ 인증서 List ]
 * @param : [OUT]int* nOutlistlen				[ 인증서 List 길이]
 * @return
 *			   성공 (0) , 실패 (Error Code)
 */
INISAFEXSAFE_API int IXL_Get_Domain_CertList (int nStoreType, unsigned char* pDriveName, int nDriveNamelen, unsigned char* pPin , int nPinlen,char* pDomain, int nDomainlen,
							 unsigned char* pFilter, int nFilterlen, unsigned char** pOutList,int* nOutlistlen);

 /**
 * @brief   : 인증서 목록 가져오기
 * @param	: [IN] int storetype				[ 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT
 * @param	: [IN] unsigned char* pDriveName	[ 저장할 드라이브 명 ]
 * @param   : [IN] int nDriveNamelen			[ 저장할 드라이브 명 길이 ]
 * @param   : [IN] unsigned char* pPin			[ PIN  정보 ]
 * @param   : [IN] int nPinlen 					[ PIN 데이터 길이 ]
 * @param	: [IN] unsigned char* pFilter		[ 필터 정보 ]
 * @param   : [IN] int nFilterlen				[ 필터 정보 길이 ]
 * @param	: [OUT]unsigned char** pOutData		[ 인증서 List ]
 * @param	: [OUT]int* nOutlistlen				[ 인증서 List 길이]
 * @return
 *			   성공 (0) , 실패 (Error Code)
 */
INISAFEXSAFE_API int IXL_Get_CertList (int nStoreType, unsigned char* pDriveName, int nDriveNamelen, unsigned char* pPin , int nPinlen,unsigned char* pFilter, int nFilterlen ,unsigned char** pOutList,int* nOutlistlen);

/**
 * @brief   : 인증서 비밀 번호 확인
 * @param	: [IN] int storetype				[ 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  정보 ]
 * @param   : [IN] int nPin 					[ PIN 데이터 길이 ]
 * @param	: [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param   : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
 * @param	: [IN] unsigned char* pPasswd		[ 비밀 번호 ]
 * @param	: [IN] int nPasswdlen				[ 비밀 번호 길이 ]
 * @param	: [OUT]unsigned char** pOutData		[ 출력 데이터  ]
 * @param	: [OUT]int* nOutDatalen				[ 출력 데이터 길이 ] 
 */
INISAFEXSAFE_API int IXL_Cert_Password_Check (int nStoreType, unsigned char* pPin, int nPin, char* pCertPath, int nCertPathlen, unsigned char* pPasswd, int nPasswdlen , unsigned char** pOutData, int* nOutlen);


/**
 * @brief   : 인증서 삭제
 * @param	: [IN] int storetype				[ 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  정보 ]
 * @param   : [IN] int nPinlen					[ PIN 데이터 길이 ]
 * @param	: [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param   : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
 */
INISAFEXSAFE_API int IXL_Cert_Delete (int nStoretype, unsigned char* pPin , int nPinlen,  char* pCertPath,int nCertPathlen);

/**
 * @brief   : 인증서 일반 보기
 * @param	: [IN] int storetype				[ 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  정보 ]
 * @param   : [IN] int nPinlen 					[ PIN 데이터 길이 ]
 * @param	: [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param   : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
 * @param	: [IN] int nvalidityCheck			[ 유효성 Check	]
 *					(1) : 체크 , (0): 체크 안함
 * @param	: [OUT]unsigned char** pOutlist		[ 인증서 일반 보기 정보 ]
 * @param	: [OUT]int* nOutlistlen				[ 인증서 일반 보기 정보 길이 ]
 * @return 
 *				성공 (0) , 실패 (Error code)
 */
INISAFEXSAFE_API int IXL_Get_CertView (int nStoreType, unsigned char* pPin , int nPinlen , char* pCertPath, int nCertPathlen,int nvalidityCheck,unsigned char** pOutlist,int* nOutlistlen);

/**
 * @brief   : 인증서 Detail 만들기 ]
 * @param   : [IN] unsigned char* pCert			[ 인증서 ]
 * @param	: [IN] int *nCertlen				[ 인증서 길이 ]
 * @param   : [OUT]unsigned char** pOutdata		[ 일반 Tab 정보 ]
 * @param   : [OUT]int* nOutlen				  	[ pOutdat 길이 ] 
 */
INISAFEXSAFE_API int IXL_Make_CertDetail (unsigned char* pCert, int nCertlen, unsigned char** pOutdata, int* nOutdata);	
	
/**
 * @brief   : 인증서 자세히 보기
 * @param	: [IN] int storetype				[ 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  정보 ]
 * @param   : [IN] int nPin 					[ PIN 데이터 길이 ]
 * @param	: [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param   : [IN] int nCertPath				[ 인증서 경로 길이 ]
 * @param	: [OUT]unsigned char** pOutdate		[ 인증서 자세히 보기 정보 ]
 * @param	: [OUt]int* nOutdata				[ 인증서 자세히 보기 정보 길이 ]
 */
INISAFEXSAFE_API int IXL_Get_CertDetail (int nStoreType, unsigned char* pPin, int nPinlen, char* pCertPath, int nCertPathlen, unsigned char** pOutdata, int* nOutlen);

/**
 * @brief   : 인증서 비밀 번호 변경
 * @param	: [IN] int nStoreType				[ 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  정보 ]
 * @param   : [IN] int nPin 					[ PIN 데이터 길이 ]
 * @param	: [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param   : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
 * @param	: [OUT]unsigned char* pOldPasswd	[ 이전 비밀 번호 ]
 * @param	: [OUT]int nOldPasswdlen			[ 이전 비밀 번호 길이 ]
 * @param	: [OUT]unsigned char* pNewPasswd	[ 새로운 비밀 번호 ]
 * @param	: [OUT]int nNewPasswdlen			[ 새로운 비밀 번호 길이 ] 
 */
INISAFEXSAFE_API int IXL_Set_CertChange_Password (int nStoreType, unsigned char* pPin, int nPin, char* pCertPath, int nCertPathlen, unsigned char* pOldPasswd, int nOldPasswdlen, unsigned char* pNewPasswd, int nNewPasswdlen);

/**
 * @brief   : 개인키 비밀 번호 변경
 * @param	: [IN] unsigned char* pPrivKey		[ 개인키 바이너리 ]
 * @param   : [IN] int nPrivKeyLen				[ 개인키 바이너리 길이 ]
 * @param	: [OUT]unsigned char* pOldPasswd	[ 이전 비밀 번호 ]
 * @param	: [OUT]int nOldPasswdlen			[ 이전 비밀 번호 길이 ]
 * @param	: [OUT]unsigned char* pNewPasswd	[ 새로운 비밀 번호 ]
 * @param	: [OUT]int nNewPasswdlen			[ 새로운 비밀 번호 길이 ] 
 */
INISAFEXSAFE_API int IXL_Set_CertChange_Password (int nStoreType, unsigned char* pPin, int nPin, char* pCertPath, int nCertPathlen, unsigned char* pOldPasswd, int nOldPasswdlen, unsigned char* pNewPasswd, int nNewPasswdlen);

/**
 * @brief   : 인증서 비밀 번호 변경(암호용 인증서 존재시 같이 암호변경한다.)
 * @param	: [IN] int nStoreType				[ 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  정보 ]
 * @param   : [IN] int nPin 					[ PIN 데이터 길이 ]
 * @param	: [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param   : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
 * @param	: [OUT]unsigned char* pOldPasswd	[ 이전 비밀 번호 ]
 * @param	: [OUT]int nOldPasswdlen			[ 이전 비밀 번호 길이 ]
 * @param	: [OUT]unsigned char* pNewPasswd	[ 새로운 비밀 번호 ]
 * @param	: [OUT]int nNewPasswdlen			[ 새로운 비밀 번호 길이 ] 
 */
INISAFEXSAFE_API int IXL_Set_CertChange_PasswordEx(int nStoreType, unsigned char* pPin, int nPin, char* pECertPath, int nECertPathlen, unsigned char* pOldPasswd, int nOldPasswdlen, unsigned char* pNewPasswd, int nNewPasswdlen);

/**
 * @brief : IXL_Get_Domain_PFXFile			[ PFX(PKCS#12) 가져오기. ]
 * @param : [IN] int nStoreType				[ Destination 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param : [IN] char* pDomain				[ 도메인 정보 ]
 * @param : [IN] int nDomainlen				[ 도메인 정보 길이 ]
 * @param : [IN] unsigned char* pP12Path	[ P12 File 경로 ]
 * @param : [IN] int nP12Pathlen			[ P12 File 경로 길이 ]
 * @param : [IN] unsigned char* pSaveDrive	[ 저장 드라이브 ]
 * @param : [IN] int nSaveDrivelen			[ 저장 드라이브 길이 ]
 * @param : [IN] unsigned char* pDestPin	[ PIN  정보 ]
 * @param : [IN] int nDestPinlen			[ PIN 데이터 길이 ]
 * @param : [IN] unsigned char* pPassword	[ 비밀 번호 ]
 * @param : [IN] int nPasswordlen			[ 비밀 번호 길이 ]
 */
INISAFEXSAFE_API int IXL_Get_Domain_PFXFile (int nDestStoreType , char* pDomain, int nDomainlen, char* pP12tPath, int nP12Pathlen,  char* pSaveDrive, int nSaveDrivelen, unsigned char* pDestPin, int nDestPinlen, unsigned char* pPassword, int nPasswordlen);



/**
 * @brief   : PFX(PKCS#12) 가져오기.
 * @param	: [IN] int nStoreType				[ Destination 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pP12Path		[ P12 File 경로 ]
 * @param   : [IN] int nP12Pathlen				[ P12 File 경로 길이 ]
 * @param	: [IN] unsigned char* pSaveDrive	[ 저장 드라이브 ]
 * @param   : [IN] int nSaveDrivelen			[ 저장 드라이브 길이 ]
 * @param   : [IN] unsigned char* pDestPin		[ PIN  정보 ]
 * @param   : [IN] int nDestPinlen				[ PIN 데이터 길이 ]
 * @param	: [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param	: [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 */
INISAFEXSAFE_API int IXL_Get_PFXFile (int nDestStoreType ,  char* pP12tPath, int nP12Pathlen,  char* pSaveDrive, int nSaveDrivelen, unsigned char* pDestPin, int nDestPinlen, unsigned char* pPassword, int nPasswordlen);

/**
* @brief   : PFX(PKCS#12) 데이터로 부터 FDD로 가져오기(인증서저장).	
* @param	: [IN] unsigned char* pP12			[ P12 데이터 ]
* @param	: [IN] int nP12len					[ P12 데이터 길이 ]
* @param	: [IN] unsigned char* pSaveDrive	[ 저장 드라이브 ]
* @param	: [IN] unsigned char* pPassword		[ 비밀 번호 ]
* @param	: [IN] int nPasswordlen				[ 비밀 번호 길이 ]
*/
INISAFEXSAFE_API int IXL_Get_FDD_PFXBuf (unsigned char* pP12, int nP12len, char* pSaveDrive, unsigned char* pPassword, int nPasswordlen);

#ifndef _IPHONE
/**
 * @brief   : Get PFX(PKCS#12) Buffer
 * @param	: [IN] unsigned char* pP12
 * @param	: [IN] int nP12len
 * @param	: [IN] int nDestStoreType
 * @param	: [IN] unsigned char* pSaveDrive            (ex:  FDD drivename , /Volumes/IAMUSB16G)
 * @param	: [IN] unsigned char* pPassword
 * @param	: [IN] int nPasswordlen				 */
INISAFEXSAFE_API int IXL_Get_PFXBuf (unsigned char* pP12, int nP12len, 
		int nDestStoreType,
		char* pSaveDrive,
		unsigned char* pPassword, int nPasswordlen);

/**
 * @brief   : Get PFX(p12) file To Memory buffer(PKI_STR_INFO)
 * @param	: [IN] unsigned char* pP12Path		
 * @param   : [IN] int nP12Pathlen			
 * @param	: [IN] unsigned char* pPassword	
 * @param	: [IN] int nPasswordlen		
 * @remark	: add by hspark . 2013.03.08
 * 			  for use only Linux , OS/X
 *			  Windows x.x Not tested
*/
INISAFEXSAFE_API int IXL_Get_PFXBuffer (
		char* pP12tPath, int nP12Pathlen,  
		unsigned char* pPassword, int nPasswordlen);

/**
 * @brief : Make PKCS#1 RSA Encrypt Value, from Memory buffer(PKI_STR_INFO)
 * @param : [IN] unsigned char* org_data		[ 서명 할 원본 데이터 ]
 * @param : [IN] int org_dataLen				[ 서명 할 원본 데이터 길이 ]
 * @param : [IN] unsigned char* pwd                    [ password of private key ]
 * @param : [IN] int pwdl                              [ length of password ]
 * @param : [OUT]unsigned char** outcert               [ PEM Type certificate ]
 * @param : [OUT]int* outcertLen                       [ length of cert ]
 * @param : [OUT]unsigned char** P1RSAEncryptedData    [ PKCS#1 RSA Encrypted data ]
 * @param : [OUT]int* P1RSAEncryptedDataLen            [ length of PKCS#1 RSA Encrypted data ]
 * @param : [OUT]unsigned char** random                [ random data]
 * @param : [OUT]int* randomLen                        [ length of random ] 		
 * @remark	: add by hspark . 2013.03.08
 * 			  for use only Linux , OS/X
 *			  Windows x.x Not tested
*/ 
INISAFEXSAFE_API int IXL_Domain_PKCS1_Cert_Submit_Buffer(
		unsigned char* org_data,int org_dataLen,
		unsigned char* pwd,int pwdl,
		unsigned char** outcert, int* outcertLen,
		unsigned char** P1RSAEncryptedData, int* P1RSAEncryptedDataLen,
		unsigned char** random, int* randomLen);

/**
 * @brief : Make PKCS#7 SignedData, from Memory buffer(PKI_STR_INFO)
 * @param : [IN] unsigned char* org_data		[ 서명 할 원본 데이터 ]
 * @param : [IN] int org_dataLen				[ 서명 할 원본 데이터 길이 ]
 * @param : [IN] unsigned char* pwd                    [ password of private key ]
 * @param : [IN] int pwdl                              [ length of password ]
 * @param : [IN] struct tm* SigningTime          [  SigningTime ]                           --> Add 
 * @param : [OUT]unsigned char** outcert               [ PEM Type certificate ]
 * @param : [OUT]int* outcertLen                       [ length of cert ]
 * @param : [OUT]unsigned char** P7SignedData			[ PKCS#1 RSA Encrypted data ]
 * @param : [OUT]int* P7SignedDataLen            [ length of PKCS#1 RSA Encrypted data ]
 * @param : [OUT]unsigned char** random                [ random data]
 * @param : [OUT]int* randomLen                        [ length of random ] 		
 * @remark	: add by hspark . 2013.03.08
 * 			  for use only Linux , OS/X
 *			  Windows x.x Not tested
*/ 
INISAFEXSAFE_API int IXL_Domain_PKCS7_Cert_Submit_Buffer(
		unsigned char* org_data,int org_dataLen,
		unsigned char* pwd,int pwdl,
		struct tm* SigningTime,
		unsigned char** outcert, int* outcertLen,
		unsigned char** P7SignedData, int* P7SignedDataLen,
		unsigned char** random, int* randomLen);

#endif


/**
 * @brief   : 인증서와 개인키를 PFX 형태(PKCS#12)로 내보내기.
 * @param	: [IN] int nStoreType				[ 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  정보 ]
 * @param   : [IN] int nPin 					[ PIN 데이터 길이 ]
 * @param	: [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param   : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
 * @param	: [IN] unsigned char* pSavePath		[ 저장 경로 ]
 * @param   : [IN] int nSavePathlen				[ 저장 경로 길이 ]
 * @param	: [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param	: [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 */
INISAFEXSAFE_API int IXL_Set_PFXFile (int storetype, unsigned char* pPin, int nPinlen, char* pCertPath, int nCertPathlen, 
									char* pSavePath, int nSavePathlen, unsigned char* pPassword, int nPasswordlen);


/**
* @brief   : 인증서와 개인키를 PFX 형태(PKCS#12)로 데이터 내보내기.
* @param	: [IN] int nStoreType				[ 저장 매체 Type ]
*					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
* @param	: [IN] unsigned char* pCertPath		[ 인증서 경로 ]
* @param   : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
* @param	: [IN] unsigned char* pPassword		[ 비밀 번호 ]
* @param	: [IN] int nPasswordlen				[ 비밀 번호 길이 ]
* @param	: [OUT] unsigned char **pPKCS12		[ PKCS#12 데이터 ]
* @param	: [OUT] int *pnLenP12				[ PKCS#12 데이터 길이 ]
*/
INISAFEXSAFE_API int IXL_Set_PFXBuf(int storetype, char* pECertPath, int nECertPathlen, unsigned char* pPassword, int nPasswordlen, unsigned char **pPKCS12, int *pnLenP12);

/**
 * @brief   : 인증서 복사
 * @param	: [IN] int nSrcStoreType			[ Source 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pSrcPin		[ Source PIN  정보 ]
 * @param   : [IN] int nsrcPinlen 				[ Source PIN 데이터 길이 ]
 * @param	: [IN] int nDestStoreType			[ Destination 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT
 * @param	: [IN] unsigned char* pDestDriveName[ Destination 드라이브 명 ]
 * @param   : [IN] int nDestDriveNamelen		[ Destination 드라이브 명 길이 ]
 * @param   : [IN] unsigned char* pDestPin		[ Destination PIN  정보 ]
 * @param   : [IN] int nDestPinlen 				[ Destination PIN 데이터 길이 ]
 * @param	: [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param   : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
 * @param	: [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param   : [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 * iOS 미제공
 */
INISAFEXSAFE_API int IXL_Cert_Copy (int nSrcStoreType,unsigned char* pSrcPin, int nSrcPinlen,int nDestStoreType, char* pDestDriveName,int nDestDriveNamelen,
									unsigned char* pDestPin, int nDestPinlen,  char* pCertPath,int nCertPathlen, unsigned char* pPassword,int nPasswordlen);


/**
 * @brief : IXL_Cert_Domain_Copy				[ 도메인 인증서 복사 ]
 * @param : [IN] char* pDomain					[ 도메인 정보 ]
 * @param : [IN] int nDomainlen					[ 도메인 정보 길이 ]
 * @param : [IN] int nSrcStoreType				[ Source 저장 매체 Type ]
 * @param : [IN] unsigned char* pSrcPin			[ Source PIN  정보 ]
 * @param : [IN] int nsrcPinlen 				[ Source PIN 데이터 길이 ]
 * @param : [IN] int nDestStoreType				[ Destination 저장 매체 Type ]
 * @param : [IN] unsigned char* pDestDriveName	[ Destination 드라이브 명 ]
 * @param : [IN] int nDestDriveNamelen			[ Destination 드라이브 명 길이 ]
 * @param : [IN] unsigned char* pDestPin		[ Destination PIN  정보 ]
 * @param : [IN] int nDestPinlen 				[ Destination PIN 데이터 길이 ]
 * @param : [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
 * @param : [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param : [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 */
INISAFEXSAFE_API int IXL_Cert_Domain_Copy (char* pDomain, int nDomainlen,int nSrcStoreType,unsigned char* pSrcPin, int nSrcPinlen,int nDestStoreType, char* pDestDriveName,int nDestDriveNamelen,
									unsigned char* pDestPin, int nDestPinlen, char* pCertPath,int nCertPathlen, unsigned char* pPassword,int nPasswordlen);

/**
 * @brief   : 본인 확인 
 * @param	: [IN] int nStoreType				[ 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pPin			[ PIN 정보 ]
 * @param	: [IN] int nPinlen					[ PIN 정보 길이 ] 
 * @param   : [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param   : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
 * @param	: [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param   : [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 * @param	: [IN] unsigned char* pSSN			[ 식별 정보 ]
 * @param	: [IN] int nSSNlen					[ 식별 정보 길이 ] 
*/
INISAFEXSAFE_API int IXL_Cert_Indentification (int storetype,unsigned char* pPin, int nPinlen, char* pCertPath, int nCertPathlen,unsigned char* pPassword,int nPasswrodlen,unsigned char* pSSN, int nSSNlen);

/**
 * @brief : IXL_Cert_Find					[ 인증서 찾기. ]
 * @param : [IN] char* pDomain				[ 도메인 정보 ]
 * @param : [IN] int nDomainlen				[ 도메인 정보 길이 ]
 * @param : [IN] unsigned char* pP12Path	[ P12 File 경로 ]
 * @param : [IN] int nP12Pathlen			[ P12 File 경로 길이 ]
 * @param : [IN] unsigned char* pPassword	[ 비밀 번호 ]
 * @param : [IN] int nPasswordlen			[ 비밀 번호 길이 ]
 * @param : [OUT]unsigned char** outlist	[ 인증서 정보 ]
 * @param : [OUT]int* outlen				[ 인증서 정보 길이 ]
 */
INISAFEXSAFE_API int IXL_Cert_Find (char* pDomain, int nDomainlen, char* pP12Path, int nP12Pathlen,unsigned char* pPassword, int nPasswordlen, unsigned char** outlist, int* outlen);

/**
 * @brief   : 로그인 인증서 제출
 * @param	: [IN] int storetype				[ 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pPin			[ PIN 정보 ]
 * @param	: [IN] int nPinlen					[ PIN 정보 길이 ] 
 * @param   : [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param   : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
 * @param	: [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param   : [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 * @param	: [IN] unsigned char* pOrgData		[ 서명 할 원본 데이터 ]
 * @param	: [IN] int nOrgDatalen				[ 서명 할 원본 데이터 길이 ]
 * @param	: [IN] int nEncodingFlag			[ OutPut Data의 Encoding 설정]
 *				(0)  Encoding 암함 , (1)  Base64 Encoding
 * @param	: [OUT]unsigned char** pDerCert		[ DER Type의 인증서, Base64 Encoding ]
 * @param	: [OUT]int* nDerCertlen				[ DER Type의 인증서 길이 ] 
 * @param	: [OUT]unsigned char** pSignData	[ 서명한 데이터  ]
 * @param	: [OUT]int* nSignDatalen			[ 서명한 데이터 길이 ] 
 * @param	: [OUT]unsigned char** pRandom		[ 'R' 데이터  ]
 * @param	: [OUT]int* nRandomlen				[ 'R' 데이터 길이 ] 
 * @param	: [OUT]unsigned char** pPadding		[ Padding Mode ]
 * @param	: [OUT]int* nPaddinglen				[ Padding Mode 길이 ] 
 * @param	: [OUT]unsigned char** pHash_alg	[ Hash 알고리즘  ]
 * @param	: [OUT]int* nHash_alg				[ Hash 알고리즘 길이 ] 
 */
INISAFEXSAFE_API int IXL_PKCS1_Cert_Submit (int nStoretype, unsigned char* pPin, int nPinlen, char* pCertPath, int nCertPathlen, unsigned char* pPassword, int nPasswordlen, unsigned char* pOrgData, int nOrgDatalen,int nEncodingflag,
						   unsigned char** pDerCert, int *nDerCertlen,unsigned char** pSignData, int* nSignDatalen, unsigned char** pRandom, int* nRandomlen,unsigned char** pPadding , int* nPadding, unsigned char** pHash_alg, int* nHash_alg);

/**
 * @brief : IXL_Domain_PKCS1_Cert_Submit               [ PKCS1 Submit , Cert advanced ]
 * @param : [IN] int storetype                         [ store type ]
 * @param : [IN] unsigned char* pin                    [ pin number of USBT or SCARD or HSM ]
 * @param : [IN] int pinl                              [ length of pin number ]
 * @param : [IN] char* ecertpath                       [ Base64 encoded cert path ]
 * @param : [IN] char* domain                          [ domain index ]
 * @param : [IN] unsigned char* pwd                    [ password of private key ]
 * @param : [IN] int pwdl                              [ length of password ]
 * @param : [IN] unsigned char* org_data               [ original data ]
 * @param : [IN] int org_datal                         [ length of original data ]
 * @param : [IN] int encodingflag                      [ Encoding Flag ]
 * @param : [OUT]unsigned char** outcert               [ PEM Type certificate ]
 * @param : [OUT]int* outcertl                         [ length of cert ]
 * @param : [OUT]unsigned char** signdata              [ PKCS#1 Sign data ]
 * @param : [OUT]int* signdatal                        [ length of data ]
 * @param : [OUT]unsigned char** random                [ random of private key ]
 * @param : [OUT]int* randoml                          [ length of random ]
 */
INISAFEXSAFE_API int IXL_Domain_PKCS1_Cert_Submit (int storetype,unsigned char* pin, int pinl, char* ecertpath,char* domain,
								  unsigned char* pwd,int pwdl,unsigned char* org_data,int org_datal,int encodingflag,
								  unsigned char** outcert, int* outcertl,unsigned char** signdata, int* signdatal,unsigned char** random, int* randoml);

/**
 * @brief   : 전자 이체 인증서 제출
 * @param	: [IN] int storetype				[ 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pPin			[ PIN 정보 ]
 * @param	: [IN] int nPinlen					[ PIN 정보 길이 ] 
 * @param   : [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param   : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
 * @param	: [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param   : [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 * @param	: [IN] unsigned char* pOrgData		[ 서명 할 원본 데이터 ]
 * @param	: [IN] int nOrgDatalen				[ 서명 할 원본 데이터 길이 ]
 * @param	: [IN] int nEncodingFlag			[ OutPut Data의 Encoding 설정]
 *				(0)  Encoding 암함 , (1)  Base64 Encoding
 * @param	: [OUT]unsigned char** pDerCert		[ DER Type의 인증서, Base64 Encoding ]
 * @param	: [OUT]int* nDerCertlen				[ DER Type의 인증서 길이 ] 
 * @param	: [OUT]unsigned char** pSignData	[ 서명한 데이터  ]
 * @param	: [OUT]int* nSignDatalen			[ 서명한 데이터 길이 ] 
 * @param	: [OUT]unsigned char** pRandom		[ 'R' 데이터  ]
 * @param	: [OUT]int* nRandomlen				[ 'R' 데이터 길이 ] 
*/
INISAFEXSAFE_API int IXL_PKCS7_Cert_Submit (int nStoretype,unsigned char* pPin, int nPinlen, char* pCertPath, int nCertPathlen, unsigned char* pPassword, int nPasswordlen, unsigned char* pOrgData, int nOrgDatalen,int nEncodingFlag,
						  unsigned char** pDerCert, int* nDerCertlen, unsigned char** pSignData, int* nSigndDatalen, unsigned char** pRandom,int* nRandomlen);

/**
 * @brief : IXL_Domain_PKCS7_Cert_submit         [ PKCS#7 Sign , Cert Advanced ]
 * @param : [IN] int storetype                   [ store type ]
 * @param : [IN] unsigned char* pin              [ pin number of USBT or SCARD or HSM ]
 * @param : [IN] int pinl                        [ length of pin number ]
 * @param : [IN] char* ecertpath                 [ base64 encoded cert path ]
 * @param : [IN] char* domain                    [ domain ]
 * @param : [IN] unsigned char* pwd              [ password of private key ]
 * @param : [IN] int pwdl                        [ length of password ]
 * @param : [IN] unsigned char* org_data         [ original data ]
 * @param : [IN] int org_datal                   [ original data length ]
 * @param : [IN] int encoding flag               [ encoding flag ]
 * @param : [OUT]unsigned char** outcert         [ DER format cert, Base64 Encoding ]
 * @param : [OUT]int* outcertl                   [ DER format cert Length ] 
 * @param : [OUT]unsigned char** outdata         [ PKCS#7 data ]
 * @param : [OUT]int* outdatal                   [ PKCS#7 data length ]
 * @param : [OUT]unsigned char** random          [ private key random data ]
 * @param : [OUT]int* outdatal                   [ random data length ]
 */
INISAFEXSAFE_API int IXL_Domain_PKCS7_Cert_submit (int storetype,unsigned char* pin,int pinl, char* ecertpath, char* domain, unsigned char* pwd,int pwdl,
								  unsigned char* org_data, int org_datal,int encodingflag, unsigned char** outcert , int* outcertl,unsigned char** outdata, int* outdatal,unsigned char** random,int* random_len );


#ifndef _IPHONE
/**
 * Add SigningTime Attribute 
 * @brief : IXL_Domain_PKCS7_Cert_submit_WithSignTimeAttribute [ PKCS#7 Sign , Cert Advanced ]
 * @param : [IN] int storetype                   [ store type ]
 * @param : [IN] unsigned char* pin              [ pin number of USBT or SCARD or HSM ]
 * @param : [IN] int pinl                        [ length of pin number ]
 * @param : [IN] char* ecertpath                 [ base64 encoded cert path ]
 * @param : [IN] char* domain                    [ domain ]
 * @param : [IN] unsigned char* pwd              [ password of private key ]
 * @param : [IN] int pwdl                        [ length of password ]
 * @param : [IN] unsigned char* org_data         [ original data ]
 * @param : [IN] int org_datal                   [ original data length ]
 * @param : [IN] int encoding flag               [ encoding flag ]
 * @param : [IN] struct tm* SigningTime          [  SigningTime ]                           --> Add 
 * @param : [OUT]unsigned char** outcert         [ DER format cert, Base64 Encoding ]
 * @param : [OUT]int* outcertl                   [ DER format cert Length ] 
 * @param : [OUT]unsigned char** outdata         [ PKCS#7 data ]
 * @param : [OUT]int* outdatal                   [ PKCS#7 data length ]
 * @param : [OUT]unsigned char** random          [ private key random data ]
 * @param : [OUT]int* outdatal                   [ random data length ]
*/

INISAFEXSAFE_API int IXL_Domain_PKCS7_Cert_submit_WithSignTimeAttribute (int storetype,
		unsigned char* pin,int pinl, 
		char* ecertpath,
		char* domain,
		unsigned char* pwd,int pwdl,
		unsigned char* org_data, int org_datal,
		struct tm* SigningTime,
		int encodingflag, unsigned char** outcert , int* outcertl,unsigned char** outdata, int* outdatal,unsigned char** random,int* random_len );


#endif

#if defined(_WIN8STORE) 
INISAFEXSAFE_API int IXL_PKCS7_Cert_With_Random (char* path,int nFlag,int nWithRandomFlag, char* recv_time, unsigned char* pPassword,int nPasswordlen,unsigned char* pOrgData, int nOrgDatalen,unsigned char** pOutData, int* nOutDatalen, unsigned char** pRandom, int* nRandomlen);
#elif defined (_IPHONE)
//#elif _IPHONE
INISAFEXSAFE_API int IXL_Verify_signature (unsigned char* cert , int certl , unsigned char* cacert, int cacertl);
INISAFEXSAFE_API int IXL_Get_ValueOfX509Field (unsigned char* cert , int certl , char* name, unsigned char** outdata, int* outdatal);
	
#endif 

/**
 * @brief   : 인증서 발급.
 * @param	: [IN] int nStoreType				[ 발급된 인증서가 저장된 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pDriveName	[ 드라이브명 , ( 'C:' 형식 ) ]
 * @param   : [IN] int nDriveNamelen			[ 드라이브명 길이 ]
 * @param	: [IN] unsigned char* pPIN			[ PIN ]
 * @param   : [IN] int nPINlen					[ PIN 길이 ]
 * @param   : [IN] unsigned char* pCAName		[ 발급을 요청할 CA 명칭 ]
 * @param   : [IN] int nCANamelen				[ 발급을 요청할 CA 명칭 길이 ]
 * @param	: [IN] unsigned char* pCAIP			[ CAIP ]
 * @param	: [IN] int nCAIPlen					[ CAIP 길이 ]
 * @param	: [IN] unsigned char* pCAPort		[ CAPort ]
 * @param	: [IN] int nCAPortlen				[ CAPort 길이 ]
 * @param	: [IN] unsigned char* pNeonCAName	[ 사설 CA Name ]
 * @param	: [IN] int nNeonCANamelen			[ 사설 CA Name 길이 ]
 * @param	: [IN] unsigned char* pNeomCAPath	[ 사설 CA 경로 ]
 * @param	: [IN] int nNeomCAPathlen			[ 사설 CA 경로 길이 ]
 * @param	: [IN] unsigned char* pRef			[ 참조 번호 ]
 * @param	: [IN] int nReflen					[ 참조 번호 길이 ]
 * @param	: [IN] unsigned char* pAuthCode		[ 인가 번호 ]
 * @param	: [IN] int nAuthcodelen				[ 인가 번호 길이 ]
 * @param	: [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param	: [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 * @param	: [IN] unsigned char* pHashAlg		[ 해쉬 알고리즘 ]
 * @param	: [IN] int nReflen					[ 해쉬 알고리즘 길이 ]
 * @param	: [IN] unsigned char* pKeyBit		[ Key 길이 ]
 * @param	: [IN] int nKeyBitlen				[ Key 길이 ]
 */
INISAFEXSAFE_API int IXL_Issue_Certificate (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,  char* pCAIP, int nCAIPlen , char* pCAPort, int nCAPortlen,
							 unsigned char* pNeonCAName , int nNeonCANamelen, unsigned char* pNeonCAPath, int nNeonCAPathlen,unsigned char* pRefVal, int nRefVallen, unsigned char* pAuthCode, int nAuthCodelen, unsigned char* pPassword, int nPasswordlen, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);



/**
 * @brief   : 인증서 재발급.
 * @param	: [IN] int nStoreType				[ 재발급된 인증서가 저장된 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pDriveName	[ 드라이브명 , ( 'C:' 형식 ) ]
 * @param   : [IN] int nDriveNamelen			[ 드라이브명 길이 ]
 * @param	: [IN] unsigned char* pPIN			[ PIN ]
 * @param   : [IN] int nPINlen					[ PIN 길이 ]
 * @param   : [IN] unsigned char* pCAName		[ 재발급을 요청할 CA 명칭 ]
 * @param   : [IN] int nCANamelen				[ 재발급을 요청할 CA 명칭 길이 ]
 * @param	: [IN] unsigned char* pCAIP			[ CAIP ]
 * @param	: [IN] int nCAIPlen					[ CAIP 길이 ]
 * @param	: [IN] unsigned char* pCAPort		[ CAPort ]
 * @param	: [IN] int nCAPortlen				[ CAPort 길이 ]
 * @param	: [IN] unsigned char* pNeonCAName	[ 사설 CA Name ]
 * @param	: [IN] int nNeonCANamelen			[ 사설 CA Name 길이 ]
 * @param	: [IN] unsigned char* pNeomCAPath	[ 사설 CA 경로 ]
 * @param	: [IN] int nNeomCAPathlen			[ 사설 CA 경로 길이 ]
 * @param	: [IN] unsigned char* pRef			[ 참조 번호 ]
 * @param	: [IN] int nReflen					[ 참조 번호 길이 ]
 * @param	: [IN] unsigned char* pAuthCode		[ 인가 번호 ]
 * @param	: [IN] int nAuthcodelen				[ 인가 번호 길이 ]
 * @param	: [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param	: [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 * @param	: [IN] unsigned char* pHashAlg		[ 해쉬 알고리즘 ]
 * @param	: [IN] int nReflen					[ 해쉬 알고리즘 길이 ]
 * @param	: [IN] unsigned char* pKeyBit		[ Key 길이 ]
 * @param	: [IN] int nKeyBitlen				[ Key 길이 ]
 */
INISAFEXSAFE_API int IXL_Replace_Certificate (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,  char* pCAIP, int nCAIPlen , char* pCAPort, int nCAPortlen,
							 unsigned char* pNeonCAName , int nNeonCANamelen, unsigned char* pNeonCAPath, int nNeonCAPathlen,unsigned char* pRefVal, int nRefVallen, unsigned char* pAuthCode, int nAuthCodelen, unsigned char* pPassword, int nPasswordlen, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);


/**
 * @brief : IXL_Replace_Certificate_Reduction	[ 인증서 재발급 (parameter 축소 )]
 * @param : [IN] int nStoreType					[ 재발급된 인증서가 저장된 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param : [IN] unsigned char* pDriveName		[ 드라이브명 , ( 'C:' 형식 ) ]
 * @param : [IN] int nDriveNamelen				[ 드라이브명 길이 ]
 * @param : [IN] unsigned char* pPIN			[ PIN ]
 * @param : [IN] int nPINlen					[ PIN 길이 ]
 * @param : [IN] unsigned char* pCAName			[ 재발급을 요청할 CA 명칭 ]
 * @param : [IN] int nCANamelen					[ 재발급을 요청할 CA 명칭 길이 ]
 * @param : [IN] unsigned char* pDn				[ DN ]
 *											사설일 경우 : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d&CANAME=%s&CAPATH=%s&CMD=RENEW
 *											공인일 경우 : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d&CMD=RENEW
 * @param : [IN] int nDnlen						[ DN 길이 ]
 * @param : [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param : [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 * @param : [IN] unsigned char* pHashAlg		[ 해쉬 알고리즘 ]
 * @param : [IN] int nReflen					[ 해쉬 알고리즘 길이 ]
 * @param : [IN] unsigned char* pKeyBit			[ Key 길이 ]
 * @param : [IN] int nKeyBitlen					[ Key 길이 ]
 */
INISAFEXSAFE_API int IXL_Replace_Certificate_Reduction (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,  char* pDn, int nDnlen,
							 unsigned char* pPassword, int nPasswordlen, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);
/**
 * @brief   : 인증서 갱신.
 * @param	: [IN] int nStoreType				[ 갱신된 인증서가 저장된 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pPIN			[ PIN ]
 * @param   : [IN] int nPINlen					[ PIN 길이 ]
 * @param	: [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param   : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
 * @param   : [IN] unsigned char* pCAName		[ 발급을 요청할 CA 명칭 ]
 * @param   : [IN] int nCANamelen				[ 발급을 요청할 CA 명칭 길이 ]
 * @param	: [IN] unsigned char* pCAIP			[ CAIP ]
 * @param	: [IN] int nCAIPlen					[ CAIP 길이 ]
 * @param	: [IN] unsigned char* pCAPort		[ CAPort ]
 * @param	: [IN] int nCAPortlen				[ CAPort 길이 ]
 * @param	: [IN] unsigned char* pNeonCAName	[ 사설 CA Name ]
 * @param	: [IN] int nNeonCANamelen			[ 사설 CA Name 길이 ]
 * @param	: [IN] unsigned char* pNeomCAPath	[ 사설 CA 경로 ]
 * @param	: [IN] int nNeomCAPathlen			[ 사설 CA 경로 길이 ]
 * @param	: [IN] unsigned char* pOldPassword	[ 이전 비밀 번호 ]
 * @param	: [IN] int nOldPasswordlen			[ 이전 비밀 번호 길이 ]
 * @param	: [IN] unsigned char* pNewPassword	[ 새로운 비밀 번호 ]
 * @param	: [IN] int nNewPasswordlen			[ 새로운 비밀 번호 길이 ]
 * @param	: [IN] unsigned char* pHashAlg		[ 해쉬 알고리즘 ]
 * @param	: [IN] int nReflen					[ 해쉬 알고리즘 길이 ]
 * @param	: [IN] unsigned char* pKeyBit		[ Key 길이 ]
 * @param	: [IN] int nKeyBitlen				[ Key 길이 ]
 */
INISAFEXSAFE_API int IXL_Update_Certificate (int nStoreType,unsigned char* pPin, int nPinlen,  char* pCertPath, int nCertPathlen, char* pCAName,int nCANamelen,  char* pCAIP, int nCAIPlen , char* pCAPort, int nCAPortlen,
							unsigned char* pNeonCAName , int nNeonCANamelen, unsigned char* pNeonCAPath, int nNeonCAPathlen,unsigned char* pOldPassword, int nOldPasswordlen,unsigned char* pNewPassword, int nNewPasswordlen, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);

/**
 * @brief : IXL_Update_Certificate_Reduction	[ 인증서 갱신(parameter 축소).]
 * @param : [IN] int nStoreType					[ 갱신된 인증서가 저장된 저장 매체 Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param : [IN] unsigned char* pPIN			[ PIN ]
 * @param : [IN] int nPINlen					[ PIN 길이 ]
 * @param : [IN] unsigned char* pCertPath		[ 인증서 경로 ]
 * @param : [IN] int nCertPathlen				[ 인증서 경로 길이 ]
 * @param : [IN] unsigned char* pCAName			[ 발급을 요청할 CA 명칭 ]
 * @param : [IN] int nCANamelen					[ 발급을 요청할 CA 명칭 길이 ]
 * @param : [IN] unsigned char* pDn				[ DN ]
 * @param : [IN] int nDnlen						[ Dn 길이 ]
 * @param : [IN] unsigned char* pOldPassword	[ 이전 비밀 번호 ]
 * @param : [IN] int nOldPasswordlen			[ 이전 비밀 번호 길이 ]
 * @param : [IN] unsigned char* pNewPassword	[ 새로운 비밀 번호 ]
 * @param : [IN] int nNewPasswordlen			[ 새로운 비밀 번호 길이 ]
 * @param : [IN] unsigned char* pHashAlg		[ 해쉬 알고리즘 ]
 * @param : [IN] int nReflen					[ 해쉬 알고리즘 길이 ]
 * @param : [IN] unsigned char* pKeyBit			[ Key 길이 ]
 * @param : [IN] int nKeyBitlen					[ Key 길이 ]
 */
INISAFEXSAFE_API int IXL_Update_Certificate_Reduction (int nStoreType,unsigned char* pPin, int nPinlen,  char* pCertPath, int nCertPathlen, char* pCAName,int nCANamelen,  char* pDn, int nDnlen,
							unsigned char* pOldPassword, int nOldPasswordlen,unsigned char* pNewPassword, int nNewPasswordlen, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);


/**
 * @brief : IXL_User_Notification			[ 인증 업무 준칙 URL ]
 * @param : [IN] int nStoreType				[ 저장 매체 타입 ]
 * @param : [IN] unsigned char* pPin		[ PIN ]
 * @param : [IN] int nPinlen				[ PIN 길이 ]
 * @param : [IN] unsigned char* pCertpath	[ 인증서 경로 ]
 * @param : [IN] int nCertPathlen			[ 인증서 경로 길이 ]
 * @param : [OUT]unsigned char** pOutData	[ 인증 업무 준칙 URL ]
 * @param : [OUT]int nOutDatalen			[ 인증 업무 준칙 URL 길이 ]
 */
INISAFEXSAFE_API int IXL_User_Notification (int nStoreType, unsigned char* pPin, int nPinlen, char* pCertPath,int nCertPathlen, unsigned char** pOutData, int* nOutDatalen);

 /**
  *	@brief	: IXL_Log							[ INISAFEXSafe Log. ]
  *	@param	: [IN] int level					[ Log Level ]
  * @param	: [IN] char* file					[ 파일 ]
  * @param	: [IN] int line						[ Line ]
  * @param	: [IN] char* format					[ 포멧 ]
  */
INISAFEXSAFE_API void IXL_Log(int level, char* file,int line, char* format, ...);

 /**
  *	@brief	: IXL_SetLogLevel					[ XSafe Log Level 설정 ]
  *	@param	: [IN] int level					[ Log Level ]
  */
INISAFEXSAFE_API void IXL_SetLogLevel (int level);

 /**
  *	@brief	: IXL_Log_HEXA						[ XSafe Log Hexa Display ]
  */
INISAFEXSAFE_API void IXL_Log_HEXA (int level, char* file,int line,unsigned char* msgname, unsigned char* content,int len);

/**
 * @brief	: IXL_Set_DomainInfo				[ 도메인 정보 설정 ]
 * @param	: [IN] unsigned char* pInfo			[ 도메인 정보  ]
 * @param	: [IN] int nInfolen					[ 도메인 정보 길이 ]
 * @return
 *		성공 : IXL_OK
 *		실패 : Error Code
 */
INISAFEXSAFE_API int IXL_Set_DomainInfo ( char* pInfo, int nInfolen);

/**
 * @brief	: IXL_Set_DomainInfo				[ 서버 인증서 설정 ]
 * @param	: [IN] unsigned char* pInfo			[ 도메인 정보  ]
 * @param	: [IN] int nInfolen					[ 도메인 정보 길이 ]
 * @param	: [IN] unsigned char* pSCert		[ 서버 인증서  ]
 * @param	: [IN] int nSCertlen				[ 서버 인증서 길이 ]
 * @return
 *		성공 : IXL_OK
 *		실패 : Error Code
 */
INISAFEXSAFE_API int IXL_Set_ServerCert ( char* pInfo, int nInfolen,unsigned char* pSCert, int nSCertlen);

/**
 * @brief	: IXL_Delete_ServerCert				[ 서버 인증서 설정 ]
 * @param	: [IN] unsigned char* pInfo			[ 도메인 정보  ]
 * @param	: [IN] int nInfolen					[ 도메인 정보 길이 ]
 * @return
 *		성공 : IXL_OK
 *		실패 : Error Code
 */
INISAFEXSAFE_API int IXL_Delete_ServerCert (unsigned char* pInfo, int nInfolen);

/**
 * @brief	: IXL_Refresh_SessionKey			[ SessionKey 재생성 ]
 * @param	: [IN] unsigned char* pInfo			[ 도메인 정보  ]
 * @param	: [IN] int nInfolen					[ 도메인 정보 길이 ]
 * @return
 *		성공 : IXL_OK
 *		실패 : Error Code
 */
INISAFEXSAFE_API int IXL_Refresh_SessionKey (unsigned char* pInfo, int nInfolen);

/**
 * @brief	: IXL_Delete_gFilter				[ Filter 정보 삭제 ]
 * @param	: [IN] unsigned char* pInfo			[ 도메인 정보  ]
 * @param	: [IN] int nInfolen					[ 도메인 정보 길이 ]
 * @return
 *		성공 : IXL_OK
 *		실패 : Error Code
 */
INISAFEXSAFE_API int IXL_Delete_gFilter (unsigned char* pInfo, int nInfolen);

/**
 * @brief	: IXL_Delete_gFilter				[ Filter 정보 삭제 ]
 * @param	: [IN] unsigned char* pInfo			[ 도메인 정보  ]
 * @param	: [IN] int nInfolen					[ 도메인 정보 길이 ]
 * @return
 *		성공 : IXL_OK
 *		실패 : Error Code
 */
INISAFEXSAFE_API int IXL_Set_gFilter (unsigned char* pInfo, int nInfolen,unsigned char* pInFilter , int nInFilterlen);

/**
 * @brief : IXL_Get_Server_SKeyAndIV            [ Get Server(WAS) session key And IV ]
 * @param : [IN] char* pInfo                    [ Domain   ]
 * @param : [OUT]unsigned char** skey           [ Server Session key ]
 * @param : [OUT]int* skeyl                     [ session key length ]
 * @param : [OUT]unsigned char** iv             [ Server Initial vector ]
 * @param : [OUT]int* ivl                       [ Initial Vector length ]
 */
INISAFEXSAFE_API int IXL_Get_Server_SKeyAndIV (char* pInfo,unsigned char** skey, int* skeyl , unsigned char** iv, int* ivl);


/**
 * @brief	: IXL_Make_InipluginData_vf0		[ VF0 INIPlugindata 생성 ]
 * @param	: [IN] char* pDomain				[ 도메인 정보  ]
 * @param	: [IN] int nDomainlen				[ 도메인 정보 길이 ]
 * @param	: [IN] unsigned char* pData_alg		[ ALG 정보 (데이터 알고리즘)  ]
 * @param	: [IN] int nData_alglen				[ ALG 정보 길이 ]
 * @param	: [IN] unsigned char* pInData		[ DT 정보(대칭키 암호화 할 데이터 )  ]
 * @param	: [IN] int nInDatalen				[ DT 정보 길이 ]
 * @param	: [OUT]unsigned char** pOutData		[ VF0 INIPlugindata ]
 * @param	: [OUT]int* nOutDatalen				[ VF0 INIPlugindata 길이]
 * @return
 *		성공 : IXL_OK
 *		실패 : Error Code
 * @remake	: 
 *		Domain 별 수신한 Server Cert의 공개키를 이용하여 RSA 암호화를 한다.
 *		Server는 수신받은 Iniplugindata 를 Server Private Key로 복호화 한다.
 */
INISAFEXSAFE_API int IXL_Make_InipluginData_VF0 (char* pDomain, int nDomainlen,char* pData_alg, 
								int nData_alglen,unsigned char* pInData, int nInDatalen, char** pOutData, int* nOutDatalen);

/**
 * @brief : IXL_Make_InipluginData_vfx0		[ VFx0 INIPlugindata 생성, VF= 10 ]
 * @param : [IN] char* domain				[ 도메인 정보  ]
 * @param : [IN] int vf						[ Verify Flag  ]
 * @param : [IN] unsigned char* indata		[ DT 정보(대칭키 암호화 할 데이터 )  ]
 * @param : [IN] int indatal				[ DT 정보 길이 ]
 * @param : [IN] unsigned char* ts			[ Time Stamp ]
 * @param : [IN] int tsl					[ Time stamp length ]
 * @param : [OUT]char** outdata				[ VF0 INIPlugindata ]
 * @param : [OUT]int* outdatal				[ VF0 INIPlugindata 길이]
 */
INISAFEXSAFE_API int IXL_Make_InipluginData_VFx0 (char* domain,int vf, unsigned char* indata, int indatal,unsigned char* ts , int tsl,
								 char** outdata, int* outdatal);
/**
 * @brief : IXL_Make_InipluginData_vfx1		[ VFx1 INIPlugindata 생성 ]
 * @param : [IN] int storetype				[ 저장 매체 타입 ]
 * @param : [IN] int vf						[ Verify Flag  ]
 * @param : [IN] unsigned char* pin			[ PIN ]
 * @param : [IN] int pinl					[ PIN Length ]
 * @param : [IN] char* ecertpath			[ Cert Path , Base64 Encoding ]
 * @param : [IN] unsigned char* pwd			[ Password ]
 * @param : [IN] int pwdl					[ Password Length ]
 * @param : [IN] char* domain				[ Domain Info  ]
 * @param : [IN] unsigned char* ts			[ Time Stamp ]
 * @param : [IN] int tsl					[ Time Stamp Length ]
 * @param : [IN] unsigned char* indata		[ DT 정보(대칭키 암호화 할 데이터 )  ]
 * @param : [IN] int indatal				[ DT 정보 길이 ]
 * @param : [OUT]char** outdata				[ VFx1 INIPlugindata ]
 * @param : [OUT]int* outdatal				[ VFx1 INIPlugindata 길이]
 */
INISAFEXSAFE_API int IXL_Make_InipluginData_VFx1 (int storetype,int vf, unsigned char* pin, int pinl, char* ecertpath,unsigned char* pwd, int pwdl,
								 char* domain,unsigned char* ts,int tsl,unsigned char* indata, int indatal,char** outdata, int* outdatal);

INISAFEXSAFE_API int IXL_Make_INIPlugindata (char* domain,int vf , int storetype,unsigned char* pin, int pinl,
                            char* Ecertpath, unsigned char* pwd, int pwdl, unsigned char* ts, int tsl,
                            unsigned char* indata, int indatal, char** outdata, int* outdatal);
								 
/**
 * @brief : IXL_Make_InipluginData_vf1			[ VF1 INIPlugindata 생성 ]
 * @param : [IN] int nStoreType					[ 저장 매체 타입 ]
 * @param : [IN] unsigned char* pPin			[ PIN ]
 * @param : [IN] int nPinlen					[ PIN 길이 ]
 * @param : [IN] unsigned char* pCertpath		[ 인증서 경로 ]
 * @param : [IN] int nCertPath					[ 인증서 경로 길이 ]
 * @param : [IN] unsigned char* pPassword		[ 비밀 번호 ]
 * @param : [IN] int nPasswordlen				[ 비밀 번호 길이 ]
 * @param : [IN] char* pDomain					[ 도메인 정보  ]
 * @param : [IN] int nDomainlen					[ 도메인 정보 길이 ]
 * @param : [IN] unsigned char* pVd				[ 서버 시간 URL ]
 * @param : [IN] int nVdlen						[ 서버 시간 URL 길이 ]
 * @param : [IN] unsigned char* pData_alg		[ ALG 정보 (데이터 알고리즘)  ]
 * @param : [IN] int nData_alglen				[ ALG 정보 길이 ]
 * @param : [IN] unsigned char* pDt				[ DT 정보(대칭키 암호화 할 데이터 )  ]
 * @param : [IN] int nDtlen						[ DT 정보 길이 ]
 * @param : [IN] unsigned char* pSign_Padding	[ 서명 Pad Mode ]
 * @param : [IN] unsigned char* pSign_alg		[ 서명 알고리즘 ]
 * @param : [OUT]unsigned char** pOutData		[ VF1 INIPlugindata ]
 * @param : [OUT]int* nOutDatalen				[ VF1 INIPlugindata 길이]
 */
INISAFEXSAFE_API int IXL_Make_InipluginData_VF1 (int nStoreType, unsigned char* pPin, int nPinlen, unsigned char* pCertPath,int nCertPathlen,
								unsigned char* pPassword, int nPasswordlen,char* pDomain,int nDomainlen,unsigned char* pVd,int nVdlen,
								unsigned char* pData_alg, int nData_alglen, unsigned char* pDt, int nDtlen,unsigned char* pSign_Padding,unsigned char* pSign_Alg,
								char** pOutData, int* nOutDatalen);

/**
 * @brief : IXL_INIPlugin_VFx_Decrypt           [ INIplugindata VF0 or VF1 Decrypt ]
 * @param : [IN] char* pDomain                  [ Domain ]
 * @param : [IN] char* pData_alg                [ data Algorithm ]
 * @param : [IN] char encode_flag               [ Input Data Decoding ]
 *										        ICL_NO_ENCODE		0x10	No encoding flag 
 *										        ICL_B64_ENCODE		0x00	Base64 encoding flag 
 *										        ICL_B64_LF_ENCODE	0x01	Base64 encoding with 'insert linefeed' flag	
 * @param : [IN] unsigned char* pDt             [ cipher data ]
 * @param : [IN] int nDtlen                     [ cipher data Length ]
 * @param : [OUT]unsigned char** pOutData       [ Plain text data ]
 * @param : [OUT]int* nOutDatalen               [ plain text data length ]
 */
INISAFEXSAFE_API int IXL_INIPlugin_VFx_Decrypt (char* pDomain ,char* pData_alg,char encode_flag, unsigned char* pDt, int nDtlen,unsigned char** pOutData,int* nOutDatalen);

/**
 * @brief	: IXL_SYM_Decrypt					[ 대칭키 복호화 ]
 * @param	: [IN] unsigned char* pDomain		[ 도메인 정보 ]
 * @param	: [IN] int nDomainlen				[ 도메인 정보 길이 ]
 * @param	: [IN] unsigned char* pData_alg		[ 대칭키 복호화 알고리즘 ]
 * @param	: [IN] int nData_alglen				[ 대칭키 복호화 알고리즘 길이 ]
 * @param	: [IN] unsigned char* pDt			[ 암호화된 데이터 (Base64&URL encoding) ]
 * @param	: [IN] int nDtlen					[ 암호화된 데이터 (Base64&URL encoding) 길이 ]
 * @param	: [OUT]unsigned char** pOutData		[ 복호화 된 데이터 ]
 * @param	: [OUT]int* nOutDatalen				[ 복호화 된 데이터 길이]
 * @return
 *		성공 : IXL_OK
 *		실패 : Error Code
 */
 INISAFEXSAFE_API int IXL_SYM_Decrypt (unsigned char* pDomain , int nDomainlen,unsigned char* pData_alg, int nData_alglen, 
	                                   unsigned char* pDt, int nDtlen,unsigned char** pOutData,int* nOutDatalen);
/**
 * @brief :	IXL_CertPath_CRL					[인증서 경로를 이용하여 인증서 유효성 검증하기 ]
 * @param : [IN] unsigned char* pCertPath		[인증서 경로]
 * @param : [IN] int nCertPathlen				[인증서 경로 길이]
 */
INISAFEXSAFE_API int IXL_CertPath_CRL ( char* pCertPath, int nCertPathlen);


/**
 * @brief	: IXL_Set_Property					[ 속성 설정 ]
 * @param	: [IN] char* pDomain				[ 도메인 정보 ]
 * @param	: [IN] int nDomainlen				[ 도메인 정보 길이]
 * @param	: [IN] unsigned char* pFieldName	[ 필드 정보 ]
 * @param	: [IN] int nFieldNamelen			[ 필드 정보 길이 ]
 * @param	: [IN] unsigned char* pValue		[ 필드에 해당하는 정보]
 * @param	: [IN] int nValuelen				[ 필드에 해당하는 정보 길이 ]
 * @return
 *		성공 : IXL_OK
 *		실패 : Error Code
 */
INISAFEXSAFE_API int IXL_Set_Property (char* pDomain, int nDomainlen, unsigned char* pFieldName, int nFieldNamelen, unsigned char* pValue, int nValuelen);

/**
* @breif : IXL_Get_Property				[ 도메인에 설정된 정보를 가져온다. ]
* @param : [IN] char *pDomain				[ 도메인 정보 ]
* @param : [IN] int nDomainlen				[ 도메인 정보 길이 ]
* @param : [IN] unsigned char *pFieldName	[ 도메인에 설정된 필드 이름 ]
* @param : [IN] int nFieldNamelen			[ 도메인에 설정된 필드 이름 길이 ]
* @param : [OUT]unsigned char **pOutData	[ 필드에 해당하는 정보 ]
* @param : [OUT]int *nOutDatalen			[ 필드에 해당하는 정보 길이 ]
*/
INISAFEXSAFE_API int IXL_Get_Property (char* pDomain, int nDomainlen, unsigned char* pFieldName,int nFieldNamelen,unsigned char** pOutData , int* nOutDatalen);

/**
 * @breif : IXL_Get_ImagePath				[ 도메인에 해당하는 이미지 파일 경로 가져오기 ]
 * @param : [IN] char* pDomain				[ 도메인 정보 ]
 * @param : [IN] int nDomainlen				[ 도메인 정보 길이 ]
 * @param : [OUT]unsgined char** pOutData	[ 이미지 경로 , Base64 encoding ]
 * @param : [OUT]int nOutDatalen			[ 이미지 경로 길이 ]
 */
INISAFEXSAFE_API int IXL_Get_ImagePath (char* pDomain, int nDomain,unsigned char** pOutData, int* nOutDatalen);

/**
 * @breif : IXL_Get_SessionKey				[ 도메인에 해당하는 Session Key 가져오기 ]
 * @param : [IN] char* pDomain				[ 도메인 정보 ]
 * @param : [IN] int nDomainlen				[ 도메인 정보 길이 ]
 * @param : [OUT]unsgined char** pOutData	[ Session Key , Base64 encoding ]
 * @param : [OUT]int nOutDatalen			[ Session Key 길이 ]
 */
INISAFEXSAFE_API int IXL_Get_SessionKey (char* pDomain, int nDomain,unsigned char** pOutData, int* nOutDatalen);

/**
 * @brief : IXL_Get_SystemDrive				[ 시스템 드라이브 정보  ]
 * @param : [OUT]unsigned char** pOutData	[ 시스템 드라이브 정보]
 *											예) drive^C&volume^ssss
 * @param : [OUT]int* nOutDatalen			[ 시스템 드라이브 정보 길이]
 */
INISAFEXSAFE_API int IXL_Get_SystemDrive (unsigned char** pOutData, int* nOutDatalen);

/**
 * @brief : IXL_Get_DriveInfos				[ 드라이브 정보 List 가져오기 ]
 * @param : [OUT]unsigned char** pOutData	[ 시스템 드라이브 정보]
 *											예) drive^C&volume^ssss
 * @param : [OUT]int* nOutDatalen			[ 시스템 드라이브 정보 길이]
 */
INISAFEXSAFE_API int IXL_Get_DriveInfos (unsigned char** pOutData, int* nOutDatalen);


/**
* @brief          : API for Message Digest
* @param        :(unsigned char *) indata: input message
* @param        :(int) indata_len: length to input message
* @param        :(unsigned char **) hash_data: hash data
* @param        :(int *) hash_len: length to hash data (return)
* @param        :(char *) hash_alg: hash algorithm name    ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2")
* @return        :(int) success=0, error=error code
*/
#if defined(_WIN8STORE) || defined(_MACOS)
INISAFEXSAFE_API int IXL_HASH_Data(unsigned char *indata, int indata_len, unsigned char **hash_data, int *hash_len, char *hash_alg);
#endif

/**
 * @brief : IXL_Delete_UserCert				[ 인증서 폐기 관련 인증서 삭제 ]
 * @param : [IN] unsinged char* pPackage	[ 인증서 종류 , CA Name (공인)or INITECH (사설) ]
 * @param : [IN] int nPackagelen			[ 인증서 종류 길이 ]
 * @param : [IN] unsigned char* pStorage	[ 저장 매체 Type ]
 * @param : [IN] int nStoragelen			[ 저장 매체 Type 길이 ]
 * @param : [IN] unsigned char* pCertValue	[ 인증서 정보 , 사설일 경우 인증서, 공인일 경우 Hexa Serial number ]
 * @param : [IN] int nCertValuelen			[ 인증서 정보 길이 ]
 */
INISAFEXSAFE_API int IXL_Delete_UserCert(unsigned char* pPackage, int nPackagelen, unsigned char* pStorage,int nStoragelen,unsigned char* pCertValue,int nCertValuelen);

/**
 * @brief : IXL_Insert_PKCS10_Cert			[ PKCS10 인증서 저장 ]
 * @param : [IN] unsigned char* pCert		[ 인증서 ]
 * @param : [IN] int nCertlen				[ 인증서 길이 ]
 */
INISAFEXSAFE_API int IXL_Insert_PKCS10_Cert (unsigned char* pCert, int nCertlen);


/**
 * @brief   : Data Encoding (Base64 or URL)
 * @param	: [IN] int nFlag						[ 인코딩 Type, 0 : Base64 , 1: URL , 2 : BASE64 And URL]
 * @param   : [IN] unsigned char* pInData			[ 입력 데이터  ]
 * @param	: [IN] int nInData						[ 입력 데이터 길이]
 * @param	: [OUT]unsigned char** pOutData			[ Encoding 된 출력 데이터 ]
 * @param   : [OUT]int* nOutlen						[ Encoding 된 출력 데이터 길이 ]
 */
INISAFEXSAFE_API int IXL_DataEncode (int nFlag , unsigned char* pInData , int nInDatalen, unsigned char **pOutData, int* nOutDatalen);

/**
 * @brief   : Data Decoding (Base64 or URL)
 * @param	: [IN] int nFlag						[ 인코딩 Type, 0 : Base64 , 1: URL , 2 : BASE64 And URL]
 * @param   : [IN] unsigned char* pInData			[ 입력 데이터  ]
 * @param	: [IN] int nInData						[ 입력 데이터 길이]
 * @param	: [OUT]unsigned char** pOutData			[ Decoding 된 출력 데이터 ]
 * @param   : [OUT]int* nOutlen						[ Decoding 된 출력 데이터 길이 ]
 */
INISAFEXSAFE_API int IXL_DataDecode (int nFlag , unsigned char* pInData , int nInDatalen, unsigned char **pOutData, int* nOutDatalen);

/**
 * @brief : IXL_COM_Change_Non_Proven		[ 비검증 모드에서 동작 ]
 */
INISAFEXSAFE_API void IXL_COM_Change_Non_Proven ();

/**
 * @brief : IXL_Generator_Random		[ Random 생성 ]
 * @param : [IN] int count				[ 생성할 Random Data 길이 ]
 * @param : [OUT]unsigned char* out		[ Random Data ]
 */
INISAFEXSAFE_API int IXL_Generator_Random (int count, unsigned char** out);

/**
 * @brief : IXL_Symmetric_Crypto		[ 대칭키 암호화 / 복호화 ]
 * @param : [IN] encrypt_flag			[ 1: 암호화 , 1이외일 경우 복호화  ]
 * @param : [IN] unsigned char* key		[ Session Key ]
 * @param : [IN] int keyl				[ Session key length ]
 * @param : [IN] unsigned char* iv		[ Initial Vector ]
 * @param : [IN] int ivl				[ Initial Vector length ]
 * @param : [IN] char* alg				[ 데이터 알고리즘 (ex)"SEED-CBC"]
 * @param : [IN] int pad_mode			[ Padding mode ]
 *										ICL_PKCS5_PAD	0x01
 * @param : [IN] char encode_flag		[ 출력 데이터의 Encoding/Decoding 설정 ]
 *										ICL_NO_ENCODE		0x10	No encoding flag 
 *										ICL_B64_ENCODE		0x00	Base64 encoding flag 
 *										ICL_B64_LF_ENCODE	0x01	Base64 encoding with 'insert linefeed' flag	
 * @param : [IN] unsigned char* indata	[ 입력 데이터 ]
 * @param : [IN] int indatal			[ 입력 데이터 길이 ]					
 * @param : [OUT]unsgined char** outdata[ 암호화 / 복호화된 데이터 ]
 * @param : [OUT]int* outdatal			[ 암호화 / 복호화된 데이터 길이 ]
 */ 
INISAFEXSAFE_API int IXL_Symmetric_Crypto (int encrypt_flag,unsigned char* key, int keyl , unsigned char* iv, int ivl,char* alg,int pad_mode,
										   char encode_flag,unsigned char* indata,int indatal,unsigned char** outdata,int*outdatal);


/**
 * @brief : IXL_RSA_Public_Crypto		[ 공개키(인증서)를 이용하여 RSA 암호화 / 복호화 ]
 * @param : [IN] encrypt_flag			[ 1: 암호화 , 1이외일 경우 복호화  ]
 * @param : [IN] unsigned char* key		[ public Key or cert ]
 * @param : [IN] int keyl				[ public Key or cert length ]
 * @param : [IN] int pad_mode			[ Padding mode ]
 *										ICL_RSAES_PKCS1_15			0x20 RSA encryption PKCS1 v1.5 ENCODE
 *										ICL_RSAES_OAEP_20			0x08 RSA encryption OAEP v2.0 ENCODE
 *										ICL_RSAES_OAEP_21			0x10 RSA encryption OAEP v2.1 ENCODE
 * @param : [IN] char encode_flag		[ 출력 데이터의 Encoding/Decoding 설정 ]
 *										ICL_NO_ENCODE		0x10	No encoding flag 
 *										ICL_B64_ENCODE		0x00	Base64 encoding flag 
 *										ICL_B64_LF_ENCODE	0x01	Base64 encoding with 'insert linefeed' flag	
 * @param : [IN]char* hash_alg			[ Hash Algorithm Name (ex) "SHA256" , (SHA1 | SHA256 | SHA512 | HAS160) ]
 * @param : [IN] unsigned char* indata	[ 입력 데이터 ]
 * @param : [IN] int indatal			[ 입력 데이터 길이 ]					
 * @param : [OUT]unsgined char** outdata[ 암호화 / 복호화된 데이터 ]
 * @param : [OUT]int* outdatal			[ 암호화 / 복호화된 데이터 길이 ]
 */
INISAFEXSAFE_API int IXL_RSA_Public_Crypto (int encrypt_flag,unsigned char* cert, int certl , char pad_mode,char encode_flag,
											char* hash_alg,unsigned char* indata,int indatal, unsigned char** outdata,int* outdatal);



/**
 * @brief : IXL_RSA_Public_Verify			[ 공개키 or 인증서를 이용하여 서명 검증]
 * @param : [IN] unsigned char* cert		[ public Key or cert]
 * @param : [IN] int certl					[ public Key or cert length ]
 * @param : [IN] int pad_mode				[ Padding mode ]
 *											ICL_NO_PAD				0x00
 *											ICL_RSASSA_PKCS1_15		0x01 RSA signature PKCS1 v1.5 ENCODE
 *											ICL_RSASSA_PSS			0x02 RSA signature PSS ENCODE
 * @param : [IN] char encode_flag			[ 출력 데이터의 Encoding/Decoding 설정 ]
 *											ICL_NO_ENCODE		0x10	No encoding flag 
 *											ICL_B64_ENCODE		0x00	Base64 encoding flag 
 *											ICL_B64_LF_ENCODE	0x01	Base64 encoding with 'insert linefeed' flag	
 * @param : [IN] char* hash_alg				[ Hash Algorithm Name (ex) "SHA256" , ("MD5" | "SHA1" | "SHA224" | "SHA256" | "SHA384" | "SHA512" | "HAS-160" | "MDC2") ]
 * @param : [IN] unsigned char* plaintext	[ plain text ]
 * @param : [IN] int plaintextl				[ plain text Length  ]					
 * @param : [IN] unsgined char* sign_data	[ Sign Data ]
 * @param : [IN] int sign_dta_len			[ Sign Data Length ]
 */
INISAFEXSAFE_API int IXL_RSA_Public_Verify (unsigned char* cert, int certl, char pad_mode, char encode_flag,char* hash_alg, unsigned char* plaintext, int plaintextl,
											unsigned char* sign_data, int sign_data_len);

/**
 * @brief : IXL_Get_ValueOfX509Field		[ 인증서를 X509형식의 인증서로 변환하여 X509 데이터를 가져온다 ]
 * @param : [IN] unsigned char* cert		[ cert ]
 * @param : [IN] int certl					[ cert length ]
 * @param : [IN] char* name					[ X509 struct의 멤버 name ]
 *											- version
 *											- serial
 *											- hexaserial
 *											- signatureAlg
 *											- issuerDN
 *											- validityFrom
 *											- validityTo
 *											- subjectDN
 *											- pubkeyalg
 *											- pubkey
 * @param : [OUT]unsigned char** outdata	[ name에 해당하는 value ]
 * @param : [OUT]int* outdatal				[ name에 해당하는 value Length ]
 */
INISAFEXSAFE_API int IXL_Get_ValueOfX509Field (unsigned char* cert , int certl , char* name, unsigned char** outdata, int* outdatal);

/**
 * @brief : IXL_Verify_signature			[ CA Cert를 이용하여 User Cert 서명 검증 ]
 * @param : [IN] unsigned char* cert		[ cert ]
 * @param : [IN] int certl					[ cert length ]
 * @param : [IN] unsigned char* cacert		[ CA Cert ]
 * @param : [IN] int cacertl				[ Length of CA Cert ]
 * @return
 *			0 : success , -1 : fail
 */
INISAFEXSAFE_API int IXL_Verify_signature (unsigned char* cert , int certl , unsigned char* cacert, int cacertl);

/**
 * @brief : IXL_Cert_Verify_Validity		[ Cert 유효성 Check ]
 * @param : [IN] unsigned char* cert		[ cert ]
 * @param : [IN] int certl					[ cert length ]
 * @return
 *			0 : success , -1 : fail
 */
INISAFEXSAFE_API int IXL_Cert_Verify_Validity (unsigned char* cert, int certl);

/**
 * @brief : IXL_ServerCert_Verify_Validity	[ Scert 유효성 Check ]
 * @param : [IN] unsigned char* scert		[ scert ]
 * @param : [IN] int scertl					[ scert length ]
 * @return
 *			0 : success , -1 : fail
 */
INISAFEXSAFE_API int IXL_ServerCert_Verify_Validity (unsigned char* scert, int scertl);
    
/**
 * @brief : IXL_Is_Cert_Advenced                [ Is Cert Advanced ]
 * @param : [IN] unsigned char* cert            [ certificate ]
 * @param : [IN] int certl                      [ Length of certificate ]
 */
INISAFEXSAFE_API int IXL_Is_Cert_Advanced (unsigned char* cert, int certl);


/**
 * @brief : IXL_Exchangekey_Decrypt            [ Exchange Key Decrypt ]
 * @param : [IN] char* domain                  [ domain info ]
 * @param : [IN] unsigned char* indata         [ enc(R1 || R2) data ]
 * @param : [IN] int indatal                   [ enc(R1 || R2) data length ]
 */
INISAFEXSAFE_API int IXL_Exchangekey_Decrypt (char* domain, unsigned char* indata,int indatal);
#ifdef WIN32

/*
 * @brief : IXL_GetSystemVersion			[ 시스템 버젼 얻기 ( Wind 용 ) ]
 * @return
 *		Fail 	(-1)
 */
INISAFEXSAFE_API int IXL_GetSystemVersion ();

/**
 * @brief : IXL_Set_HSM_Drive					[ 사용할 보안 토큰 설저어 ]
 * @param : [IN] char* pDomain					[ 도메인 정보 ]
 * @param : [IN] int nDomainlen					[ 도메인 정보 길이 ]
 * @param : [IN] unsigned char* pUSBTModule		[ 보안 토큰 모듈  ex: "C:\\WINDOWS\\system32\\eTPKCS11.dll"]
 * @param : [IN] int nUSBTModulelen				[ 보안 토큰 모듈 길이 ]
 * @return
 *			성공 : IXL_OK
 *			실패 : Error code
 */
INISAFEXSAFE_API int IXL_Set_HSM_Drive (char* pDomain, int nDomainlen,unsigned char* pHSMModule, int nHSMModulelen);

/**
 * @brief : IXL_HSM_Status						[ 보안 토큰 상태 Check ]
 * @param : [IN] unsigned char* pInHSMUrl		[ 보안 토큰 상태 Check를 위한 URL 주소 ]
 * @param : [IN] int nInHSMUrllen				[ 보안 토큰 상태 Check를 위한 URL 주소 길이 ]
 * @param : [OUT]unsigned char** pOutdata		[ 보안 토큰 상태 결과값 ]
 *												[ 보안 토근 연결 X , 드라이버 설치 X : URL 주소]
 *												[ 보안 토큰 연결 O , 드라이버 설치 O : 보안 토큰 정보]
 *												[ 보안 토큰 정보 : 보안 토큰 이름&모듈명&드라이버 설치 유무&설치 경로]
 * @param : [OUT]int* nOutdatalen				[ 보안 토큰 상태 결과값 길이 ]
 * @return
 *			성공 : 보안 토큰이 연결 되고, 보안 토큰 드라이버가 설치 되었으면 IXL_OK return
 *			실패 : 보안 토큰이 연결 안되고, 보안 토큰 드라이버가 설치 되지 않았으면 IXL_NOK (pOutData NULL)
 *			       보안 토큰이 연결 되고, 보안 토큰 드라이버가 설치 되지 않았으면, Error Code & pOutData 전달
 */
INISAFEXSAFE_API int IXL_HSM_Status(unsigned char* pInHSMUrl, int nInHSMUrllen, unsigned char** pOutData, int* nOutDatalen);

/**
 * @brief : IXL_Get_SaveToken_DeviceType       [ Save Token Device Type ]
 * @param : [IN] int storetype                 [ storage Type ( SCARD / USBT ) ]
 * @param : [OUT]int* type                     [ Device type ]
 */
INISAFEXSAFE_API int IXL_Get_SaveToken_DeviceType (int storetype,int* outtype);

/**
 * @brief : IXL_Check_Complexity_Password      [ password check ]
 * @param : [IN] char *pSrc                    [ password ]
 */
//INISAFEXSAFE_API int IXL_Check_Complexity_Password(char* pSrc);

    
#endif

// add by junsoon.ahn 2015.06.15
// S-PinPad용 함수
#ifdef _IPHONE
/**
 * @brief : IXL_SpinKeyCleanup        [ S-Pinpad용 공개키 메모리 해제 ]
 */
INISAFEXSAFE_API void IXL_SpinKeyCleanup(void);
    
/**
 * @brief : IXL_SpinKeyCheck        [ S-Pinpad용 공개키 설정 여부 체크 ]
 */
INISAFEXSAFE_API int IXL_SpinKeyCheck(void);
    
/**
 * @brief : IXL_InitSpinKey                 [ S-Pinpad용 암복호화용 공개키 초기화 ]
 * @param : [IN]unsigned char* publicKey    [ S-Pinpad public key Data ]
 * @param : [IN]int publicKeyLen            [ S-Pinpad public key Length ]
 */
INISAFEXSAFE_API int IXL_InitSpinKey(unsigned char *publicKey, int publicKeyLen);

/**
 * @brief : IXL_SetSPinPublicKey        [ S-Pinpad용 암복호화용 공개키 초기화 ]
 * @param : [IN]NSString *publicKey     [ S-Pinpad public key Data ]
 */
INISAFEXSAFE_API int IXL_SetSPinPublicKey(NSString *publicKey);
    
/**
 * @brief : IXL_GetSpinkey              [ 키체인에서 인증서와 S-Pinpad용 개인키 추출 ]
 * @param : [IN] int idx                [ certificate index ]
 * @param : [OUT]unsigned char** cert   [ certificate Data ]
 * @param : [OUT]int* certlen           [ certificate Length ]
 * @param : [OUT]unsigned char** pkey   [ S-Pinpad private key Data ]
 * @param : [OUT]int* pkeylen           [ S-Pinpad private key Length ]
 */
INISAFEXSAFE_API int IXL_GetSpinkey(int idx, unsigned char **cert, int *certlen, unsigned char **pkey, int *pkeylen);
    
/**
 * @brief : IXL_Save_SPinkey                [ S-Pinpad용 개인키 복사 ]
 * @param : [IN] int idx                    [ certificate index ]
 * @param : [IN] const char *password       [ 원본 개인키 비밀번호 ]
 * @param : [IN] const char *newPassword    [ S-Pinpad용 개인키 비밀번호 ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Save_SPinkey (int idx, const char *password, const char *newPassword);
    
/**
 * @brief : IXL_Save_SPinkey            [ S-Pinpad용 개인키 복사 ]
 * @param : [IN] int idx                [ certificate index ]
 * @param : [IN] NSData *password       [ 원본 개인키 비밀번호 ]
 * @param : [IN] NSData *newPassword    [ S-Pinpad용 개인키 비밀번호 ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Save_SPinkey (int idx, NSData *password, NSData *newPassword);
    
/**
 * @brief : IXL_DeleteSPinkey         [ S-Pinpad용 개인키 삭제 ]
 * @param : [IN] int idx            [ certificate index ]
 */
INISAFEXSAFE_API int IXL_DeleteSPinkey(int idx);
    
/**
 * @brief : IXL_FindSpinkey         [ S-Pinpad용 개인키 존재 여부 확인 ]
 * @param : [IN] int idx            [ certificate index ]
 */
INISAFEXSAFE_API int IXL_FindSpinkey(int idx);
    
/**
 * @brief : IXL_CheckSpinkey        [ S-Pinpad용 개인키 비밀번호 체크 및 존재 여부 확인 ]
 * @param : [IN] int idx            [ certificate index ]
 * @param : [IN] char *password     [ S-Pinpad용 개인키 비밀번호 ]
 * @param : [IN] int passwordlen    [ S-Pinpad용 개인키 비밀번호 길이 ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_CheckSpinkey(int idx, char *password, int passwordlen);
    
/**
 * @brief : IXL_CheckSpinkey        [ S-Pinpad용 개인키 비밀번호 체크 및 존재 여부 확인 ]
 * @param : [IN] int idx            [ certificate index ]
 * @param : [IN] NSData *password   [ S-Pinpad용 개인키 암호화된 비밀번호 ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_CheckSpinkey(int idx, NSData* password);
    
/**
 * @brief : IXL_ChangePasswdSpinkey         [ S-Pinpad용 개인키 비밀번호 변경 ]
 * @param : [IN] int idx                    [ certificate index ]
 * @param : [IN] const char* password       [ S-Pinpad용 이전 비밀번호 ]
 * @param : [IN] const char* newPassword    [ S-Pinpad용 새 비밀번호 ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_ChangePasswdSpinkey(int idx, const char* password, const char* newPassword);
    
/**
 * @brief : IXL_ChangePasswdSpinkey         [ S-Pinpad용 개인키 비밀번호 변경 ]
 * @param : [IN] int idx                    [ certificate index ]
 * @param : [IN] NSData* password           [ S-Pinpad용 암호화된 이전 비밀번호 ]
 * @param : [IN] NSData* newPassword        [ S-Pinpad용 암호화된 새 비밀번호 ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_ChangePasswdSpinkey(int idx, NSData* password, NSData* newPassword);
    
/**
 * @brief : IXL_PKCS7_Cert_With_Random           [ PKCS#7 Sign , Cert Advanced , keypad(NFilter, S-PinPad) 지원]
 * @param : [IN] int idx                         [ certificate index ]
 * @param : [IN] int nWithRandomFlag             [ OutPut Data의 WithRandom 설정 ]
 *                                                  (0) WithRandom 안함,   (1) WithRandom
 * @param : [IN] struct tm *recv_time            [ received time ]
 * @param : [IN] unsigned char* pwd              [ password of private key ]
 * @param : [IN] int pwdl                        [ length of password ]
 * @param : [IN] unsigned char* org_data         [ original data ]
 * @param : [IN] int org_datal                   [ original data length ]
 * @param : [IN] int encoding flag               [ encoding flag ]
 * @param : [OUT]unsigned char** outcert         [ DER format cert, Base64 Encoding ]
 * @param : [OUT]int* outcertl                   [ DER format cert Length ]
 * @param : [OUT]unsigned char** outdata         [ PKCS#7 data ]
 * @param : [OUT]int* outdatal                   [ PKCS#7 data length ]
 * @param : [IN] int keypadflag                  [ NFilter : 0, S-PinPad : 1 ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_PKCS7_Cert_With_Random (int idx, int nWithRandomFlag, struct tm *recv_time, unsigned char* pwd,int pwdl, unsigned char* org_data, int org_datal,int encodingflag, unsigned char** outcert , int* outcertl, unsigned char** outdata, int* outdatal, int keypadflag);

/**
 * @brief : IXL_PKCS7_Cert_With_Random           [ PKCS#7 Sign , Cert Advanced , keypad(NFilter, S-PinPad) 암호화된 비밀번호 지원]
 * @param : [IN] int idx                         [ certificate index ]
 * @param : [IN] int nWithRandomFlag             [ OutPut Data의 WithRandom 설정 ]
 *                                                  (0) WithRandom 안함,   (1) WithRandom
 * @param : [IN] struct tm *recv_time            [ received time ]
 * @param : [IN] NSData* pwd                     [ encrypted password of private key ]
 * @param : [IN] unsigned char* org_data         [ original data ]
 * @param : [IN] int org_datal                   [ original data length ]
 * @param : [IN] int encoding flag               [ encoding flag ]
 * @param : [OUT]unsigned char** outcert         [ DER format cert, Base64 Encoding ]
 * @param : [OUT]int* outcertl                   [ DER format cert Length ]
 * @param : [OUT]unsigned char** outdata         [ PKCS#7 data ]
 * @param : [OUT]int* outdatal                   [ PKCS#7 data length ]
 * @param : [IN] int keypadflag                  [ NFilter : 0, S-PinPad : 1 ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_PKCS7_Cert_With_Random (int idx, int nWithRandomFlag, struct tm *recv_time, NSData* pwd, unsigned char* org_data, int org_datal,int encodingflag, unsigned char** outcert , int* outcertl, unsigned char** outdata, int* outdatal, int keypadflag);

#endif
    


#define	IXL_OK									0
#define IXL_NOK									-1

#define OPENDIR_ERROR							1051000
#define GETALLCERTHEADER_PARAM_ERROR			1051001
#define LISTSTR_MALLOC_FAIL						1051002
#define CERT_INFO_MEMALLOC_ERROR				1051003
#define GETSERIAL_X509_ERROR					1051004
#define X509GETSUBJECTDN_PARAM_ERROR			1051005			
#define X509GETSUBJECTNAME_ERROR				1051006
#define SKINFO_MALLOC_ERROR						1051007
#define ENVELOPED_ENC_WITHSKEYIV_BASE64_ERROR	1051008
#define CERT_DIGEST_ERROR						1051009
#define SYMENCRYPT_ERROR						1051010
#define SYMDECRYPT_ERROR						1051011
#define INITSKIDARRAY_PARAM_ERROR				1051012
#define GETSKEYIV_PARAM_ERROR					1051013
#define NOTFOUND_SKID_ERROR						1051014	
#define ENVELOPED_DEC_WITHSKEYIV_ERROR			1051015
#define ADDSKEYIV_PARAM_ERROR					1051016
#define ENVELOPED_ENC_PARAM_ERROR				1051017
#define SYMENCRYPT_PARAM_ERROR					1051018
#define SYMENCRYPT_GETSKEYIV_ERROR				1051019

#define ENC_CERTANDKEY_DECRYPT_ERROR			1051020
#define ENC_CERTANDKEY_PARSE_ERROR				1051021
#define IXL_MALLOC_ERROR						1051022
#define PRIVKEY_BASE64_DECODING_ERROR			1051023
#define LOAD_X509_ERROR							1051024
#define FAIL_SAVE_TO_IPHONE_KEYCHAIN			1051025
#define INDEX_NOT_VALID							1051026
#define CH_PASSWORD_FAIL						1051027
#define PASSWORD_CHANGED_PKEY_SAVE_FAIL			1051028
#define GET_RANDOM_FROM_PKEY_FAIL				1051029
#define INVALID_VID								1051030
#define DELETE_FAIL_FROM_IPHONE_KEYCHAIN		1051031
#define GET_CERTPKEY_FROM_IPHONE_FAIL			1051032
#define PKEY_READ_ERROR							1051033
#define PKEY_PASSWORD_INCORRECT					1051034
#define CHECKVID_PARAM_ERROR					1051035
#define CHECKPOP_PARAM_ERROR					1051036
#define DECRYPT_ERROR							1051037
#define SETINIPLUGINPROPERTY_PARAM_ERROR		1051039
#define SID_NULL								1051040
#define MAKEINIPLUGINDATA_PARAM_ERROR			1051041
#define IPDECRYPT_PARAM_ERROR					1051042
#define ENC_CERTANDKEY_ENCRYPT_ERROR			1051043
#define NO_MATCH_CA_CERTS                       1051044
#define FAIL_TO_VERIFY_A_CERT                   1051045
#define CERT_NOT_YET_VALID                      1051046
#define CERT_EXPIRED                            1051047
    
/* manwoo.cho add 2010.09.14 */
#define BUFFER_OVERFLOW_ERROR					1051038
	
#define DLL_LOAD_ERROR							1052000
#define DLL_GET_FUNCTION_ERROR					1052001
#define FAIL_TO_VERIFY_INDATA                   1052004
#define VIERIFY_INDATA_PARAM_ERROR				1052005
#define VIERIFY_ORG_DATA_LEN_ERROR				1052006
#define MEMORY_ALLOCATE_ERROR					1052007
#define PIN_PARAMETER_ERROR						1052008
#define PATH_PARAMETER_ERROR					1052009
#define PATH_AND_LEN_ERROR						1052010
#define IXL_INVALID_ARGUMENT_ERROR				1052011
#define DATA_HASH_ERROR							1052012
#define	INVALID_PASSWORD_ERROR					1052013
#define INVALID_CERT_ERROR						1052014
#define INVALID_DATA_ERROR						1052015
#define CA_NAME_PARAMETER_ERROR					1052016
#define CA_IP_PARAMETER_ERROR					1052017
#define CA_Port_PARAMETER_ERROR					1052018
#define CA_URL_PARAMETER_ERROR					1052019
#define CA_URLPATH_PARAMETER_ERROR				1052020
#define REF_VAL_PARAMETER_ERROR					1052021
#define AUTH_CODE_PARAMETER_ERROR				1052022
#define CMP_ISSUE_CERTITICATE_ERROR				1052023
#define CMP_REPLACE_CERTITICATE_ERROR			1052024
#define CMP_UPDATE_CERTITICATE_ERROR			1052025
#define FILTER_TYPE_ERROR						1052026
#define DRIVE_NAME_ERROR						1052027
#define ORIGINAL_SIGN_DATA_ERROR				1052028
#define SSN_DATA_ERROR							1052029
#define READ_FILE_ERROR							1052030
#define WRITE_FILE_ERROR						1052031
#define X509_CERT2DER_ERROR						1052032
#define PK1_SIGN_ERROR							1052033
#define PK7_SIGN_ERROR							1052034
#define GET_PK12_ERROR							1052035
#define SET_PK12_ERROR							1052036
#define RANDOM_DATA_ERROR						1052037
#define GEN_SESSIONKEY_ERROR					1052038
#define DOMAIN_INFO_ERROR						1052039
#define CTX_NULL								1052040
#define SERVER_CERT_EXIST						1052041
#define SERVER_CERT_NOT_EXIST					1052042
#define SESSIONKEY_EXIST						1052043
#define SESSIONKEY_NOT_EXIST					1052044
#define FILTER_INFO_EXIST						1052045
#define FILTER_INFO_NOT_EXIST					1052046
#define DOMAIN_NOT_FOUND						1052047
#define IV_EXIST								1052048
#define IV_NOT_EXIST							1052049
#define PUBLICKEY_NOT_EXIST						1052050

#define SIGN_TO_BINARY_ERROR					1052051
#define SERVERTIME_ERROR						1052052
#define HASH_ERROR								1052053
#define STATUS_NOT_SETUP_DRIVER_ERROR			1052054
#define STATUS_NOT_FOUND_STORAGE_ERROR			1052055
#define STATUS_DRIVER_NOT_READY_ERROR			1052056
#define STATUS_STORAGE_ERROR					1052057
#define STATUS_SESSION_ERROR					1052058
#define STATUS_SIGNED_ERROR						1052059
#define STATUS_LOGIN_ERROR						1052060
#define STATUS_LOCK_ERROR						1052061
#define HSM_MODULE_ERROR						1052062
#define CERT_COPY_ERROR							1052063
#define CERT_REMOVE_ERROR						1052064
#define CERT_PKCS1_ERROR						1052065
#define PHONE_NAME_NOT_EXIST					1052066
#define PHONE_URL_NOT_EXIST						1052067
#define PHONE_VERSION_NOT_EXIST					1052068
#define CPS_URL_NOT_FOUND						1052069
#define NOT_FOUND_IMAGE_PATH					1052070
#define CMP_PKCS10_ISSUE_CERTITICATE_ERROR		1052071
#define NOT_FOUND_PKCS10_STRUCT					1052072
#define INVALID_PIN_ERROR						1052073
#define INVALID_PIN_AND_PWD_ERROR				1052074
#define MEMORY_CAPACITY_LACK					1052075
#define DISCORD_DEVICETYPE						1052076
#define NOT_SUPPORT_DEVICE						1052077
#define R1_VERIFY_FAIL							1052078
#define INVALID_NOT_ALPHABET_PASSWORD           1052079
#define INVALID_EIGHT_UNDER_PASSWORD            1052080
#define INVALID_ALL_PASSWORD                    1052081
    
#define IXL_NFILTER_NOK                         1052082
#define GET_PK12_NOT_MATCHED_PASSWORD_ERROR		1052083
#define GET_PK12_INVALID_PKCS12_FORMAT_ERROR	1052084
#define GET_PK12_INVALID_ASN1_FORMAT_ERROR      1052085
    
#define IXL_SPECIAL_CHARACTER_INVALID_ARGUMENT_ERROR    1052086
    
#define IXL_SIGN_CERT_NOT_EXIST                 1052087
    
#define INVALID_VID_LENGTH						1052088

#define NFILTER_DECRYPT_FAIL                    1053001
#define GET_NFILTER_PUBKEY_FAIL                 1053002
    
#define SPINPAD_DECRYPT_FAIL                    1053021        // S-Pinpad용 암호용 비밀번호 복호화 실패
#define GET_SPINPAD_PUBKEY_FAIL                 1053022        // S-Pinpad용 비밀번호 암/복호 공개키가 없음
#define NOT_EXIST_SPINPADKEY                    1053023        // S-Pinpad용 개인키가 키체인에 없음
#define SPINPADKEY_PASSWORD_INCORRECT           1053024        // S-Pinpad용 개인키 비밀번호 틀림
#define SPINPADKEY_COPY_SAVE_FAIL               1053025        // S-Pinpad용 개인키 복사 실패
#define PASSWORD_CHANGED_SPINPADKEY_SAVE_FAIL   1053026        // S-Pinpad용 개인키 비밀번호 변경 실패
#define GET_CERTSPINPADKEY_FROM_IOS_FAIL        1053027        // S-Pinpad용 개인키 추출 실패
#define FAIL_DELETE_SPINKEY_IPHONE_KEYCHAIN     1053028        // S-Pinpad용 개인키 삭제 실패

#define BASE64_DECODING_ERROR                   1053030
    


#define MSG_OPENDIR_ERROR					"Directory open 실패"
#define MSG_GETALLCERTHEADER_PARAM_ERROR	"인증서리스트 가져오기 실패. path 확인"
#define MSG_LISTSTR_MALLOC_FAIL				"인증서 리스트 스트링 가져오기 실패. 메모리할당 실패"
#define MSG_CERT_INFO_MEMALLOC_ERROR		"인증서 정보저장 구조체 생성 실패."
#define MSG_GETSERIAL_X509_ERROR			"인증서에서 Serial Number 가져오기 실패."
#define MSG_X509GETSUBJECTDN_PARAM_ERROR	"인증서에서 SubjectDN을 가져오는데 실패. 인증서 파라미터가 널"
#define MSG_X509GETSUBJECTNAME_ERROR		"인증서에서 SubjectName을 가져오는데 실패."
#define MSG_SKINFO_MALLOC_ERROR				"SKID 구조체 생성 실패."
#define MSG_ENVELOPED_ENC_WITHSKEYIV_BASE64_ERROR	"Enveloped Encrypt (skey,iv포함) 실패"
#define MSG_CERT_DIGEST_ERROR				"SKID 배열초기화 하던중 인증서를 해쉬하는데 실패"
#define MSG_SYMENCRYPT_ERROR				"대칭키 암호화 실패"
#define MSG_SYMDECRYPT_ERROR				"대칭키 복호화 실패"
#define MSG_BUFFER_OVERFLOW_ERROR			"버퍼 오버플로우 오류"
#define MSG_INITSKIDARRAY_PARAM_ERROR		"SKID 구조체 배열 Init 실패. 파라미터 확인"
#define MSG_GETSKEYIV_PARAM_ERROR			"세션키 IV 가져오기 실패. 파라미터 SKID NULL"
#define MSG_NOTFOUND_SKID_ERROR				"찾고자하는 SKID가 저장되어있지 않음."
#define MSG_ENVELOPED_DEC_WITHSKEYIV_ERROR	"세션키와 IV 갖는 Enveloped Decrypt 실패"
#define MSG_ADDSKEYIV_PARAM_ERROR			"세션키와 IV 저장 실패. 인증서스트링이 NULL"
#define MSG_ENVELOPED_ENC_PARAM_ERROR		"Enveloped Encrypt 실패. 파라미터 skid가 NULL"
#define MSG_SYMENCRYPT_PARAM_ERROR			"대칭키 암호화 실패. 파라미터 skid가 NULL"
#define MSG_SYMENCRYPT_GETSKEYIV_ERROR		"대칭키 복호화 실패. skid 와 매칭되는 세션키 IV를 찾을수 없음."
#define MSG_IXL_UNKNOWN_ERROR				"정의되지 않은 에러 메시지 입니다."

#define MSG_ENC_CERTANDKEY_DECRYPT_ERROR	"암호화된 개인키 및 인증서를 복호화 하는데 실패"
#define MSG_ENC_CERTANDKEY_PARSE_ERROR		"복호화된 개인키&인증서 파싱 실패"
#define MSG_IXL_MALLOC_ERROR				"메모리 할당 실패"
#define MSG_PRIVKEY_BASE64_DECODING_ERROR	"파싱된 개인키 base64 디코딩 실패"
#define MSG_LOAD_X509_ERROR					"X509 정보 파싱 실패"
#define MSG_FAIL_SAVE_TO_IPHONE_KEYCHAIN	"IPhone Keychain 에 인증서&키를 저장 실패"
#define MSG_INDEX_NOT_VALID					"유효한 인덱스 번호가 아닙니다."
#define MSG_CH_PASSWORD_FAIL				"비밀번호 변경 실패"
#define MSG_PASSWORD_CHANGED_PKEY_SAVE_FAIL	"비밀번호 변경이 완료된 개인키 파일 저장 실패"
#define MSG_GET_RANDOM_FROM_PKEY_FAIL		"개인키에서 랜덤 추출 실패"
#define MSG_INVALID_VID						"VID 검증 실패"
#define MSG_DELETE_FAIL_FROM_IPHONE_KEYCHAIN	"IPhone Keychain의 인증서&개인키 삭제 실패"
#define MSG_GET_CERTPKEY_FROM_IPHONE_FAIL	"IPhone Keychain으로 부터 개인키&인증서 가져오기 실패"
#define MSG_PKEY_READ_ERROR					"인덱스 번째 개인키를 하드디스크로 부터 읽어오기 실패"
#define MSG_PKEY_PASSWORD_INCORRECT			"개인키 비밀번호 틀림"
#define MSG_CHECKVID_PARAM_ERROR			"VID 검증 파라미터 오류"
#define MSG_CHECKPOP_PARAM_ERROR			"개인키 비밀번호 검증 파라미터 오류"
#define MSG_DECRYPT_ERROR					"인증서 복호화 오류: 주민번호, 인증번호 입력 확인"
#define MSG_SETINIPLUGINPROPERTY_PARAM_ERROR		"iniplugindata property set parameter error"
#define MSG_SID_NULL								"sid is null"
#define MSG_MAKEINIPLUGINDATA_PARAM_ERROR			"MakeINIPluginData Parameter error"
#define MSG_IPDECRYPT_PARAM_ERROR					"IPDecrypt Parameter error"	
	
/* manwoo.cho add */
#define MSG_DLL_LOAD_ERROR					"DLL 로드 오류"
#define MSG_DLL_GET_FUNCTION_ERROR			"DLL 함수 호출 오류"
#define MSG_FAIL_TO_VERIFY_INDATA           "이미지 검증 실패" 
#define MSG_VIERIFY_INDATA_PARAM_ERROR		"이미지 검증 데이터 오류"
#define MSG_VIERIFY_ORG_DATA_LEN_ERROR		"이미지 검증 원본 데이터 길이 오류"
#define MSG_MEMORY_ALLOCATE_ERROR			"메모리 할당 오류"
#define MSG_PIN_PARAMETER_ERROR				"PIN 파라미터 오류 & PIN 길이 오류"
#define MSG_PATH_PARAMETER_ERROR			"경로 파라미터 오류 & 경로 길이 오류"
#define MSG_PATH_AND_LEN_ERROR				"Path 데이터와 Path 길이 정보가 일치하지 않는다."
#define MSG_IXL_INVALID_ARGUMENT_ERROR		"입력 파라미터 오류 "
#define MSG_DATA_HASH_ERROR					"입력 데이터를 Hash하는 도중 오류 발생"
#define MSG_INVALID_PASSWORD_ERROR			"입력 비밀 번호 오류"
#define MSG_INVALID_CERT_ERROR				"지원하지 않는 인증서 Type"
#define MSG_INVALID_DATA_ERROR				"데이터 오류"
#define MSG_CA_NAME_PARAMETER_ERROR			"CA Name 파라미터 오류"
#define MSG_CA_IP_PARAMETER_ERROR			"CA IP 파라미터 오류"
#define MSG_CA_Port_PARAMETER_ERROR			"CA Port 파라미터 오류"
#define MSG_CA_URL_PARAMETER_ERROR			"CA URL 파라미터 오류"
#define MSG_CA_URLPATH_PARAMETER_ERROR		"CA URL Path 파라미터 오류"
#define MSG_REF_VAL_PARAMETER_ERROR			"참조 코드 파라미터 오류"
#define MSG_AUTH_CODE_PARAMETER_ERROR		"인가 코드 파라미터 오류"
#define MSG_CMP_ISSUE_CERTITICATE_ERROR		"CMP LIB 인증서 발급 오류"
#define MSG_CMP_REPLACE_CERTITICATE_ERROR	"CMP LIB 인증서 재발급 오류"
#define MSG_CMP_UPDATE_CERTITICATE_ERROR	"CMP LIB 인증서 갱신 오류"
#define MSG_FILTER_TYPE_ERROR				"정의 되지 않은 Filter Type"
#define MSG_DRIVE_NAME_ERROR				"드라이브 명이 정확하지 않습니다."
#define MSG_ORIGINAL_SIGN_DATA_ERROR		"서명을 위한 원본 데이터 오류"
#define MSG_SSN_DATA_ERROR					"식별 정보 오류"
#define MSG_READ_FILE_ERROR					"파일 읽어오기 실패"
#define MSG_WRITE_FILE_ERROR				"파일 쓰기 실패"
#define MSG_X509_CERT2DER_ERROR				"Cert to DER 변환 오류"
#define MSG_PK1_SIGN_ERROR					"로그인(PKCS#1) 서명 오류"
#define MSG_PK7_SIGN_ERROR					"이체(PKCS#7) 서명 오류"
#define MSG_GET_PK12_ERROR					"PKCS#12 가져오기 오류"
#define MSG_SET_PK12_ERROR					"PKCS#12 내보내기 오류"
#define MSG_RANDOM_DATA_ERROR				"Random Data 오류"
#define MSG_GEN_SESSIONKEY_ERROR			"SessionKey 생성 실패"
#define MSG_DOMAIN_INFO_ERROR				"도메인 정보 오류"
#define MSG_CTX_NULL						"CTX 구조체 NULL"
#define MSG_SERVER_CERT_EXIST				"서버 인증서 존재함"
#define MSG_SERVER_CERT_NOT_EXIST			"서버 인증서 존재하지 않음"
#define MSG_IXL_OK							"성공"
#define MSG_IXL_NOK							"실패"
#define MSG_SESSIONKEY_EXIST				"SessionKey 존재함"
#define MSG_SESSIONKEY_NOT_EXIST			"SessionKey 존재하지 않음"
#define MSG_FILTER_INFO_EXIST				"필터 정보가 존재함"
#define MSG_FILTER_INFO_NOT_EXIST			"필터 정보가 존재하지 않음"
#define MSG_DOMAIN_NOT_FOUND				"도메인 정보가 존재하지 않음"
#define MSG_IV_EXIST						"Initial Vector 존재 함"
#define MSG_IV_NOT_EXIST					"Initial Vector 존재하지 않음"
#define MSG_PUBLICKEY_NOT_EXIST				"서버 인증서의 공개키가 존재하지 않음"

#define MSG_SIGN_TO_BINARY_ERROR			"보안 토큰 서명 DER 생성 실패"
#define MSG_SERVERTIME_ERROR				"PKCS#7 서명 시간 오류"
#define MSG_HASH_ERROR						"해쉬 실패"
#define MSG_STATUS_NOT_SETUP_DRIVER_ERROR	"드라이버를 찾을 수 없음"
#define MSG_STATUS_NOT_FOUND_STORAGE_ERROR	"장치를 찾을 수 없음"
#define MSG_STATUS_DRIVER_NOT_READY_ERROR	"드라이버를 설치 할 수 없음"

#define MSG_STATUS_STORAGE_ERROR			"보안 토큰 장치 오류"
#define MSG_STATUS_SESSION_ERROR			"보안 토큰 Session 오류"
#define MSG_STATUS_SIGNED_ERROR				"보안 토큰 전자 서명 오류"
#define MSG_STATUS_LOGIN_ERROR				"보안 토큰 로그인 오류"
#define MSG_STATUS_LOCK_ERROR				"보안 토큰이 잠겨 있습니다."
#define MSG_HSM_MODULE_ERROR				"모듈명 오류"

#define MSG_CERT_COPY_ERROR					"인증서 복사 실패"
#define MSG_CERT_REMOVE_ERROR				"인증서 삭제 실패"
#define MSG_CERT_PKCS1_ERROR				"인증서 PKCS#1 서명 실패"

#define MSG_PHONE_NAME_NOT_EXIST			"휴대폰 드라이버 정보가 없음"
#define MSG_PHONE_URL_NOT_EXIST				"휴대폰 드라이버 다운로드 URL 정보가 없음"
#define MSG_PHONE_VERSION_NOT_EXIST			"휴대폰 드라이버 버젼 정보가 없음"
#define MSG_CPS_URL_NOT_FOUND				"인증 업무 준칙 URL 정보가 없습니다."
#define MSG_NOT_FOUND_IMAGE_PATH			"이미지 파일 경로가 존재하지 않습니다."
#define MSG_CMP_PKCS10_ISSUE_CERTITICATE_ERROR	"CMP LIB PKCS10 인증서 발급 오류"
#define MSG_NOT_FOUND_PKCS10_STRUCT			"PKCS10 구조체를 찾을 수 없습니다"
#define MSG_INVALID_PIN_ERROR				"PIN 번호 오류"
#define MSG_INVALID_PIN_AND_PWD_ERROR		"PIN 혹은 새로운 비밀 번호 오류"
#define MSG_MEMORY_CAPACITY_LACK			"HSM 메모리 용량 부족"
#define MSG_DISCORD_DEVICETYPE				"저장매체 Type 불일치"
#define MSG_NOT_SUPPORT_DEVICE				"지원하지 않는 디바이스"
#define MSG_R1_VERIFY_FAIL					"R1 검증 실패"
#define MSG_INVALID_NOT_ALPHABET_PASSWORD           "인증서 비밀번호는 영문을 반드시 포함하셔야 합니다."
#define MSG_INVALID_EIGHT_UNDER_PASSWORD            "인증서 비밀번호는 반드시 8자리 이상 입력하셔야 합니다."
#define MSG_INVALID_ALL_PASSWORD					"인증서 비밀번호는 영문을 반드시 포함하여 8자리 이상 입력하셔야 합니다."

#define MSG_GET_PK12_NOT_MATCHED_PASSWORD_ERROR     "PKCS#12 가져오기 오류 (비밀번호 불일치)"
#define MSG_GET_PK12_INVALID_PKCS12_FORMAT_ERROR    "PKCS#12 가져오기 오류 (PKCS12 형식이 아님)"
#define MSG_GET_PK12_INVALID_ASN1_FORMAT_ERROR      "PKCS#12 가져오기 오류 (잘못된 데이터)"

#define MSG_IXL_SPECIAL_CHARACTER_INVALID_ARGUMENT_ERROR    "허용되지 않는 특수문자 사용"
    
#define MSG_IXL_SIGN_CERT_NOT_EXIST     "서명용 인증서가 존재하지 않음"
    
#define MSG_INVALID_VID_LENGTH					"VID 길이 초과"
    
#define MSG_BASE64_DECODING_ERROR	"base64 디코딩 실패"
    
#ifdef  __cplusplus
}
#endif

#endif 
