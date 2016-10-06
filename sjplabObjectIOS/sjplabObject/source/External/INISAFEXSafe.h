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
#define KM_CERT_TYPE            0       /* ��ȣ�� ������ Ÿ�� */
#define SIGN_CERT_TYPE          1       /* ���ο� ������ Ÿ�� */
    
/* StoreType Cert Flag*/
#define ROOT_CA_CERT_FLAG		0		/* �ֻ��� ���� ��� */
#define ROOT_CERT_FLAG			1		/* ROOT ������ */
#define CA_CERT_FLAG			2		/* CA ������ */

#define	ENCODE_URL_OR_BASE64	1		/* 0 : BASE64 , 1 : URL , 2 : BASE64+URL */

#define ENCODE_BASE64			0		/* Base64 Encoding */
#define ENCODE_URL				1		/* URL Encoding */
#define ENCODE_BASE64_URL		2		/* BASE64+url Encoding */

#if defined(WIN32)
#ifdef WINCE
#define LOADLIBRARY			L"INISAFECMP.dll"	// sangwon.hont add : WINCE�� wide char�� ����.
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
	char issuer[256];					/* �߱��� */
	char issuerDN[256];					/* �߱��� */
	char subject[256];					/* ������ CN */
	char serialNumber[256];				/* Serial Number */
	char certificatePoliciesOID[256];	/* OID */
	char OIDString[256];				/* OID String */
	char issueDate[256];				/* �߱� ���� */
	char expireDate[256];				/* ���� ���� */
	char certpath[256];					/* ������ ��� */
	char pkeypath[256];					/* ����Ű ��� */

	char caname[256];					/* CA Name */
	int expiredflag;					/* ��ȿ :0 , ���� : 1 ,���� : 2 */
	int nFlag;							/* ��� : 0 , ��� ���� : 1*/
	int ncertype;						/* 1. NPKI , 2. PPKI, 3.GPKI */



#ifdef _WIN8STORE
	// ȭ�鿡 �����ֱ����� ������
	// ���͸��� �ʿ��� ���� �ΰ����� ��� �ִ� ����ü �̴�.
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
 *	������ ����Ʈ ����ü
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
 *	@brief	: IXL_DeleteAllList					[ ������ ���� ����Ʈ ���� ]
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
 * @brief : IXL_Get_Issue_Certificate_PKCS10[ PKCS10 ������ �߱� ���� �������� ]
 * @param : [IN] int nStoreType				[ �߱޵� �������� ����� ���� ��ü Type ]
 * @param : [IN] unsigned char* pDriveName	[ ����̺�� , ('C:' ���� ) ]
 * @param : [IN] int nDriveNamelen			[ ����̺�� ���� ]
 * @param : [IN] unsigned char* pPIN		[ PIN ]
 * @param : [IN] int nPINlen				[ PIN ���� ]
 * @param : [IN] unsigned char* pCAName		[ �߱��� ��û�� CA ��Ī ]
 * @param : [IN] int nCANamelen				[ �߱��� ��û�� CA ��Ī ���� ]
 * @param : [IN] unsigned char* pDn			[ DN ]
 *											�缳�� ��� : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d&CANAME=%s&CAPATH=%s
 *											������ ��� : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d
 * @param : [IN] int nDnlen					[ DN ���� ]
 * @param : [IN] unsigned char* pPassword	[ ��� ��ȣ ]
 * @param : [IN] int nPasswordlen			[ ��� ��ȣ ���� ]
 * @param : [OUT]unsigned char** pOutData	[ PKCS10 ���� ]
 * @param : [OUT]int* nOutDatalen			[ PKCS10 ���� ���� ]
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
 * @brief : IXL_Get_Issue_Certificate_PKCS10[ PKCS10 ������ �߱� ���� �������� ]
 * @param : [IN] int nStoreType				[ �߱޵� �������� ����� ���� ��ü Type ]
 * @param : [IN] unsigned char* pDriveName	[ ����̺�� , ('C:' ���� ) ]
 * @param : [IN] int nDriveNamelen			[ ����̺�� ���� ]
 * @param : [IN] unsigned char* pPIN		[ PIN ]
 * @param : [IN] int nPINlen				[ PIN ���� ]
 * @param : [IN] unsigned char* pCAName		[ �߱��� ��û�� CA ��Ī ]
 * @param : [IN] int nCANamelen				[ �߱��� ��û�� CA ��Ī ���� ]
 * @param : [IN] unsigned char* pDn			[ DN ]
 *											�缳�� ��� : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d&CANAME=%s&CAPATH=%s
 *											������ ��� : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d
 * @param : [IN] int nDnlen					[ DN ���� ]
 * @param : [IN] unsigned char* pPassword	[ ��� ��ȣ ]
 * @param : [IN] int nPasswordlen			[ ��� ��ȣ ���� ]
 * @param : [OUT]unsigned char** pOutData	[ PKCS10 ���� ]
 * @param : [OUT]int* nOutDatalen			[ PKCS10 ���� ���� ]
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
 * @brief   : KeyCain���κ��� PFX(PKCS#12) �����ͷ� ��������(��������������).
 * @param	: [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param	: [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
 * @param	: [OUT] unsigned char** pP12		[ P12 ������ ]
 * @param	: [OUT] int *nP12len				[ P12 ������ ���� ]
 */
INISAFEXSAFE_API int IXL_Get_PFXBuf_KeyChain (int idx, unsigned char* pPassword, int nPasswordlen, unsigned char **pP12, int *nP12len);
/**
 * @brief   : PFX(PKCS#12) �����ͷ� ���� KeyChain���� ��������(����������).
 * @param	: [IN] unsigned char* pP12			[ P12 ������ ]
 * @param	: [IN] int nP12len					[ P12 ������ ���� ]
 * @param	: [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param	: [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
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
 * @brief : IXL_Issue_Certificate_Reduction		[ ������ �߱�. (Parameter ���) ]
 * @param : [IN] int nStoreType					[ �߱޵� �������� ����� ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT
 * @param : [IN] unsigned char* pDriveName		[ ����̺�� , ('C:' ���� ) ]
 * @param : [IN] int nDriveNamelen				[ ����̺�� ���� ]
 * @param : [IN] unsigned char* pPIN			[ PIN ]
 * @param : [IN] int nPINlen					[ PIN ���� ]
 * @param : [IN] unsigned char* pCAName			[ �߱��� ��û�� CA ��Ī ]
 * @param : [IN] int nCANamelen					[ �߱��� ��û�� CA ��Ī ���� ]
 * @param : [IN] unsigned char* pDn				[ DN ]
 *											�缳�� ��� : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d&CANAME=%s&CAPATH=%s
 *											������ ��� : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d
 * @param : [IN] int nDnlen						[ DN ���� ]
 * @param : [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param : [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
 * @param : [IN] unsigned char* pHashAlg		[ �ؽ� �˰��� ]
 * @param : [IN] int nReflen					[ �ؽ� �˰��� ���� ]
 * @param : [IN] unsigned char* pKeyBit			[ Key ���� ]
 * @param : [IN] int nKeyBitlen					[ Key ���� ]
 */
INISAFEXSAFE_API int IXL_Issue_Certificate_Reduction (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,
                                                                                    char* pDn, int nDnlen, unsigned char* pPassword, int nPasswordlen, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);
/**
 * @brief : IXL_RSA_Private_Sign		[ ����Ű�� �̿��Ͽ� ���� ]
 * @param : [IN] unsigned char* key		[ private Key ]
 * @param : [IN] int keyl				[ private Key length ]
 * @param : [IN] int pad_mode			[ Padding mode ]
 *										ICL_NO_PAD				0x00
 *										ICL_RSASSA_PKCS1_15		0x01 RSA signature PKCS1 v1.5 ENCODE
 *										ICL_RSASSA_PSS			0x02 RSA signature PSS ENCODE
 * @param : [IN] char encode_flag		[ ��� �������� Encoding/Decoding ���� ]
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
 * @brief : IXL_RSA_Private_Crypto		[ ����Ű�� �̿��Ͽ� RSA ��ȣȭ / ��ȣȭ ]
 * @param : [IN] encrypt_flag			[ 1: ��ȣȭ , 1�̿��� ��� ��ȣȭ  ]
 * @param : [IN] unsigned char* key		[ private Key ]
 * @param : [IN] int keyl				[ private key length ]
 * @param : [IN] unsigned char* pwd		[ private key password ]
 * @param : [IN] int pwdl				[ private key password length ]
 * @param : [IN] int pad_mode			[ Padding mode ]
 *										ICL_RSAES_PKCS1_15			0x20 RSA encryption PKCS1 v1.5 ENCODE
 *										ICL_RSAES_OAEP_20			0x08 RSA encryption OAEP v2.0 ENCODE
 *										ICL_RSAES_OAEP_21			0x10 RSA encryption OAEP v2.1 ENCODE
 * @param : [IN] char encode_flag		[ ��� �������� Encoding/Decoding ���� ]
 *										ICL_NO_ENCODE		0x10	No encoding flag
 *										ICL_B64_ENCODE		0x00	Base64 encoding flag
 *										ICL_B64_LF_ENCODE	0x01	Base64 encoding with 'insert linefeed' flag
 * @param : [IN]char* hash_alg			[ Hash Algorithm Name (ex) "SHA256" , (SHA1 | SHA256 | SHA512 | HAS160) ]
 * @param : [IN] unsigned char* indata	[ �Է� ������ ]
 * @param : [IN] int indatal			[ �Է� ������ ���� ]
 * @param : [OUT]unsgined char** outdata[ ��ȣȭ / ��ȣȭ�� ������ ]
 * @param : [OUT]int* outdatal			[ ��ȣȭ / ��ȣȭ�� ������ ���� ]
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
 * @param : [IN] int nWithRandomFlag             [ OutPut Data�� WithRandom ���� ]
 *              (0) WithRandom ����,   (1) WithRandom
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
 * @brief : IXL_Check_MinLength                 [ ���� �ּ� ���� üũ ]
 * @param : [IN] const unsigned char* password	[ ��й�ȣ ]
 * @param : [IN] const int passlen              [ ��й�ȣ ���� ]
 * @param : [IN] int minlength                  [ ��й�ȣ ���� �ּ� ���� ]
 * return : ������ ��� : IXL_OK , �������� ���� ���; IXL_NOK
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_MinLength(const unsigned char* password, const int passlen, int minlength);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_MinLength(NSData* password, int minlength);
/**
 * @brief : IXL_Check_MaxLength                 [ ���� �ִ� ���� üũ ]
 * @param : [IN] const unsigned char* password	[ ��й�ȣ ]
 * @param : [IN] const int passlen              [ ��й�ȣ ���� ]
 * @param : [IN] int maxlength                  [ ��й�ȣ ���� �ִ� ���� ]
 * return : ������ ��� : IXL_OK , �������� ���� ���; IXL_NOK
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_MaxLength(const unsigned char* password, const int passlen, int maxlength);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_MaxLength(NSData* password, int maxlength);
/**
 * @brief : IXL_Check_Continous_Letter			[ ���ӵ� ���� üũ (������, ����)]
 * @param : [IN] const unsigned char* password	[ ��й�ȣ ]
 * @param : [IN] const int passlen              [ ��й�ȣ ���� ]
 * @param : [IN] int checklength				[ ��й�ȣ ���ӵ� ���� ���� ���� ]
 * return : ������ ��� : IXL_OK , �������� ���� ���; IXL_NOK
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Continous_Letter(const unsigned char* password, const int passlen, int checklength);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Continous_Letter(NSData* password, int checklength);
/**
 * @brief : IXL_Check_Continous_Reverse_Digit	[ �������� ���ӵ� ���� üũ ]
 * @param : [IN] const unsigned char* password	[ ��й�ȣ ]
 * @param : [IN] const int passlen              [ ��й�ȣ ���� ]
 * @param : [IN] int checklength				[ ��й�ȣ ���ӵ� ���� ���� ���� ]
 * return : ������ ��� : IXL_OK , �������� ���� ���; IXL_NOK
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Continous_Reverse_Digit(const unsigned char* password, const int passlen, int checklength);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Continous_Reverse_Digit(NSData* password, int checklength);
/**
 * @brief : IXL_Check_Repeated_Letter           [ �ݺ� ���� ���� üũ ]
 * @param : [IN] const unsigned char* password	[ ��й�ȣ ]
 * @param : [IN] const int passlen              [ ��й�ȣ ���� ]
 * @param : [IN] int repeatcnt                  [ ��й�ȣ ������ ���� ���� ���� ]
 * return : ������ ��� : IXL_OK , �������� ���� ���; IXL_NOK
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Repeated_Letter(const unsigned char* password, const int passlen, int repeatcnt);
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Check_Repeated_Letter(NSData* password, int repeatcnt);
/**
 * @brief : IXL_Check_Type_Of_Character         [ ��������Ư������ ȥ�� üũ ]
 * @param : [IN] const unsigned char* password	[ ��й�ȣ ]
 * @param : [IN] const int passlen              [ ��й�ȣ ���� ]
 * return : ������ ��� : IXL_OK , �������� ���� ���; IXL_NOK
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
 * @brief : IXL_Keychain_Update_Cert			[ ������ ����(iOS�� Űü�� ����).]
 * @param : [IN] int idx						[ ������ ����Ʈ index ]
 * @param : [IN] unsigned char* pCAName			[ ������ ��û�� CA ��Ī ]
 * @param : [IN] int nCANamelen					[ ������ ��û�� CA ��Ī ���� ]
 * @param : [IN] unsigned char* pDn				[ DN ]
 * @param : [IN] int nDnlen						[ Dn ���� ]
 * @param : [IN] unsigned char* pOldPassword	[ ���� ��� ��ȣ ]
 * @param : [IN] int nOldPasswordlen			[ ���� ��� ��ȣ ���� ]
 * @param : [IN] unsigned char* pNewPassword	[ ���ο� ��� ��ȣ ]
 * @param : [IN] int nNewPasswordlen			[ ���ο� ��� ��ȣ ���� ]
 * @param : [IN] unsigned char* pHashAlg		[ �ؽ� �˰��� ]
 * @param : [IN] int nReflen					[ �ؽ� �˰��� ���� ]
 * @param : [IN] unsigned char* pKeyBit			[ Key ���� ]
 * @param : [IN] int nKeyBitlen					[ Key ���� ]
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
 ���� iPhone �������� ȣȯ�� ���� �Լ� �߰�. 
    encryptedMsg : ������ ���� ���۵� ��ȣȭ�� ����Ű+������
    encryptedMsglen : encryptedMsg �� ����
    regnum : �ֹε�Ϲ�ȣ 13�ڸ� 
    verifyid : ������ȣ 16�ڸ�
 */
#if defined(_INI_BADA) 
INISAFEXSAFE_API int IXL_DecryptAndSave(unsigned char *encryptedMsg, int encryptedMsglen, char *regnum, char *verifyid, const char* path);
#elif defined (_WIN8STORE) 
INISAFEXSAFE_API int IXL_DecryptAndSave(unsigned char *encryptedMsg, int encryptedMsglen, char *regnum, char *verifyid, char* pwd);
#else
INISAFEXSAFE_API int IXL_DecryptAndSave(unsigned char *encryptedMsg, int encryptedMsglen, char *regnum, char *verifyid);				
#endif

    
    
/**
 * @brief : IXL_ServerCert_Verify_Validity	[ SCert ��ȿ�� Check ]
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
 * @brief   : ���̳ʸ��� �̿��� ����Ű ��� ��ȣ ����
 * @param   : [IN] unsigned char* pPrivKey			[ ����Ű ������ ]
 * @param	: [IN] int nPrivKeyLen					[ ����Ű ������ ���� ]
 * @param   : [IN] unsigned char* pPassword			[ ������ ��� ��ȣ ]
 * @param	: [IN] int nPassword					[ ������ ��� ��ȣ  ����]
  */
INISAFEXSAFE_API int IXL_Priv_PassWord_Check (unsigned char* pPrivKey, int nPrivKeyLen, unsigned char* pPassword , int nPassword);

/**
 * @brief : IXL_Get_Cert_AlgorithmAndHash		[ �������� Hash �� Algorthm �������� ]
 * @param : [IN] int type						[ kx : 0 , sg : 1 ]
 * @param : [IN] unsigned char* cert			[ ������ ]
 * @param : [IN] int certl						[ ������ ���� ]
 * @param : [OUT] char** alg					[ Algorithm ]
 * @param : [OUT] char** hash_alg				[ Hash Algorithm ]
 */
int IXL_Get_Cert_AlgorithmAndHash (int type, unsigned char* cert, int certl, char** alg, char** hash_alg);
	
/**
 * @brief :	IXL_Image_Verify_Signed			[ �̹��� ���� ���� ]
 * @param : [IN] char* pDomain				[ ������ ���� ]
 * @param : [IN] int nDomainlen				[ ������ ���� ���� ]
 * @param : [IN] unsigned char* pURI		[ �̹��� URI , http �� ����. Base64 encoding �� ������ ]
 * @param : [IN] int nURI					[ �̹��� URI ���� ]
 * @param : [OUT]unsigned char** pOut		[ �̹��� ���� ��ġ , Base64 encoding ]
 * @param : [OUT]int* nOutlen				[ �̹��� ���� ��ġ ���� ]
 * @remark
 *  �̹��� URI�� ���� �޾� �̹��� ���� ������ ���� �Ѵ�.
 *  �̹��� ���� ������ �����ϸ�, Local �� �̹��� ������ �����ϰ� ���� ��ġ�� Return �Ѵ�.
 */
INISAFEXSAFE_API int IXL_Image_Verify_Signed (char* pDomain, int nDomainlen,unsigned char* pURI, int nURIlen, unsigned char** pOut,int *nOutlen);

/**
 * @brief :	IXL_Image_Verify			    [ �̹��� ���� ���� ]
 * @param : [IN] unsigned char* pImageData	[ ����� �̹��� Data ]
 * @param : [IN] int nImageDatalen			[ ����� �̹��� Data ���� ]
 * @param : [OUT]unsigned char** pOut		[ �̹��� ���� Data ]
 * @param : [OUT]int* nOutlen				[ �̹��� ���� Data ���� ]
 * @remark
 *  ����� �̹��� Data�� �޾� �̹��� ���� ������ ���� �Ѵ�.
 *  �̹��� ���� ������ �����ϸ�, �̹��� ���� Data�� Return �Ѵ�.
 */
INISAFEXSAFE_API int IXL_Image_Verify (unsigned char* pImageData, int nImageDatalen, unsigned char** pOut,int *nOutlen);


/**
 * @brief :	IXL_Downloaded_Image_Verify		[ �ٿ�ε��� �̹��� ������ ���� ���� ]
 * @param : [IN] char *downloaded_ImagePath	[ �̹��� ���� Path]
 * @remark
 *  add by hspark . 2013.09.13
 *  �̹� �ٿ�ε� ���� �̹��� ������ �̿��Ͽ� ���� ������ �Ѵ�.
 *	���� ������ �����ϸ� IXL_OK ����
 */
INISAFEXSAFE_API int IXL_Downloaded_Image_Verify(char *downloaded_ImagePath);


/**
 * @brief :	IXL_AppSign_Verify		
 * @param : [IN] char *tarGet_fileName		[ ���� ��� ����]
 * @param : [IN] char *sig_fileName		[ ���� ��� ���ϰ� ¦�� �Ǵ� ���� ����]
 * @remark 
 *  add by hspark . 2013.10.08
 *  ������ ������ ���Ͽ� ���� ���� ��� ���ϰ� �� ������ ������ ���������� ���Ͽ� ������ �����Ѵ�.
 *  ��/������������ ����Ѵ�.
 *	���� ������ �����ϸ� IXL_OK ����
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
 * @brief : IXL_Get_Domain_CertList				[ (������) ������ ��� �������� ]
 * @param : [IN] int storetype					[ ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param : [IN] unsigned char* pDriveName		[ ������ ����̺� �� ]
 * @param : [IN] int nDriveNamelen				[ ������ ����̺� �� ���� ]
 * @param : [IN] unsigned char* pPin			[ PIN  ���� ]
 * @param : [IN] int nPinlen 					[ PIN ������ ���� ]
 * @param : [IN] char* pDomain					[ ������ ���� ]
 * @param : [IN] int nDomainlen					[ ������ ���� ���� ]
 * @param : [IN] unsigned char* pFilter			[ ���� ���� ]
 * @param : [IN] int nFilterlen					[ ���� ���� ���� ]
 * @param : [OUT]unsigned char** pOutData		[ ������ List ]
 * @param : [OUT]int* nOutlistlen				[ ������ List ����]
 * @return
 *			   ���� (0) , ���� (Error Code)
 */
INISAFEXSAFE_API int IXL_Get_Domain_CertList (int nStoreType, unsigned char* pDriveName, int nDriveNamelen, unsigned char* pPin , int nPinlen,char* pDomain, int nDomainlen,
							 unsigned char* pFilter, int nFilterlen, unsigned char** pOutList,int* nOutlistlen);

 /**
 * @brief   : ������ ��� ��������
 * @param	: [IN] int storetype				[ ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT
 * @param	: [IN] unsigned char* pDriveName	[ ������ ����̺� �� ]
 * @param   : [IN] int nDriveNamelen			[ ������ ����̺� �� ���� ]
 * @param   : [IN] unsigned char* pPin			[ PIN  ���� ]
 * @param   : [IN] int nPinlen 					[ PIN ������ ���� ]
 * @param	: [IN] unsigned char* pFilter		[ ���� ���� ]
 * @param   : [IN] int nFilterlen				[ ���� ���� ���� ]
 * @param	: [OUT]unsigned char** pOutData		[ ������ List ]
 * @param	: [OUT]int* nOutlistlen				[ ������ List ����]
 * @return
 *			   ���� (0) , ���� (Error Code)
 */
INISAFEXSAFE_API int IXL_Get_CertList (int nStoreType, unsigned char* pDriveName, int nDriveNamelen, unsigned char* pPin , int nPinlen,unsigned char* pFilter, int nFilterlen ,unsigned char** pOutList,int* nOutlistlen);

/**
 * @brief   : ������ ��� ��ȣ Ȯ��
 * @param	: [IN] int storetype				[ ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  ���� ]
 * @param   : [IN] int nPin 					[ PIN ������ ���� ]
 * @param	: [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param   : [IN] int nCertPathlen				[ ������ ��� ���� ]
 * @param	: [IN] unsigned char* pPasswd		[ ��� ��ȣ ]
 * @param	: [IN] int nPasswdlen				[ ��� ��ȣ ���� ]
 * @param	: [OUT]unsigned char** pOutData		[ ��� ������  ]
 * @param	: [OUT]int* nOutDatalen				[ ��� ������ ���� ] 
 */
INISAFEXSAFE_API int IXL_Cert_Password_Check (int nStoreType, unsigned char* pPin, int nPin, char* pCertPath, int nCertPathlen, unsigned char* pPasswd, int nPasswdlen , unsigned char** pOutData, int* nOutlen);


/**
 * @brief   : ������ ����
 * @param	: [IN] int storetype				[ ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  ���� ]
 * @param   : [IN] int nPinlen					[ PIN ������ ���� ]
 * @param	: [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param   : [IN] int nCertPathlen				[ ������ ��� ���� ]
 */
INISAFEXSAFE_API int IXL_Cert_Delete (int nStoretype, unsigned char* pPin , int nPinlen,  char* pCertPath,int nCertPathlen);

/**
 * @brief   : ������ �Ϲ� ����
 * @param	: [IN] int storetype				[ ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  ���� ]
 * @param   : [IN] int nPinlen 					[ PIN ������ ���� ]
 * @param	: [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param   : [IN] int nCertPathlen				[ ������ ��� ���� ]
 * @param	: [IN] int nvalidityCheck			[ ��ȿ�� Check	]
 *					(1) : üũ , (0): üũ ����
 * @param	: [OUT]unsigned char** pOutlist		[ ������ �Ϲ� ���� ���� ]
 * @param	: [OUT]int* nOutlistlen				[ ������ �Ϲ� ���� ���� ���� ]
 * @return 
 *				���� (0) , ���� (Error code)
 */
INISAFEXSAFE_API int IXL_Get_CertView (int nStoreType, unsigned char* pPin , int nPinlen , char* pCertPath, int nCertPathlen,int nvalidityCheck,unsigned char** pOutlist,int* nOutlistlen);

/**
 * @brief   : ������ Detail ����� ]
 * @param   : [IN] unsigned char* pCert			[ ������ ]
 * @param	: [IN] int *nCertlen				[ ������ ���� ]
 * @param   : [OUT]unsigned char** pOutdata		[ �Ϲ� Tab ���� ]
 * @param   : [OUT]int* nOutlen				  	[ pOutdat ���� ] 
 */
INISAFEXSAFE_API int IXL_Make_CertDetail (unsigned char* pCert, int nCertlen, unsigned char** pOutdata, int* nOutdata);	
	
/**
 * @brief   : ������ �ڼ��� ����
 * @param	: [IN] int storetype				[ ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  ���� ]
 * @param   : [IN] int nPin 					[ PIN ������ ���� ]
 * @param	: [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param   : [IN] int nCertPath				[ ������ ��� ���� ]
 * @param	: [OUT]unsigned char** pOutdate		[ ������ �ڼ��� ���� ���� ]
 * @param	: [OUt]int* nOutdata				[ ������ �ڼ��� ���� ���� ���� ]
 */
INISAFEXSAFE_API int IXL_Get_CertDetail (int nStoreType, unsigned char* pPin, int nPinlen, char* pCertPath, int nCertPathlen, unsigned char** pOutdata, int* nOutlen);

/**
 * @brief   : ������ ��� ��ȣ ����
 * @param	: [IN] int nStoreType				[ ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  ���� ]
 * @param   : [IN] int nPin 					[ PIN ������ ���� ]
 * @param	: [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param   : [IN] int nCertPathlen				[ ������ ��� ���� ]
 * @param	: [OUT]unsigned char* pOldPasswd	[ ���� ��� ��ȣ ]
 * @param	: [OUT]int nOldPasswdlen			[ ���� ��� ��ȣ ���� ]
 * @param	: [OUT]unsigned char* pNewPasswd	[ ���ο� ��� ��ȣ ]
 * @param	: [OUT]int nNewPasswdlen			[ ���ο� ��� ��ȣ ���� ] 
 */
INISAFEXSAFE_API int IXL_Set_CertChange_Password (int nStoreType, unsigned char* pPin, int nPin, char* pCertPath, int nCertPathlen, unsigned char* pOldPasswd, int nOldPasswdlen, unsigned char* pNewPasswd, int nNewPasswdlen);

/**
 * @brief   : ����Ű ��� ��ȣ ����
 * @param	: [IN] unsigned char* pPrivKey		[ ����Ű ���̳ʸ� ]
 * @param   : [IN] int nPrivKeyLen				[ ����Ű ���̳ʸ� ���� ]
 * @param	: [OUT]unsigned char* pOldPasswd	[ ���� ��� ��ȣ ]
 * @param	: [OUT]int nOldPasswdlen			[ ���� ��� ��ȣ ���� ]
 * @param	: [OUT]unsigned char* pNewPasswd	[ ���ο� ��� ��ȣ ]
 * @param	: [OUT]int nNewPasswdlen			[ ���ο� ��� ��ȣ ���� ] 
 */
INISAFEXSAFE_API int IXL_Set_CertChange_Password (int nStoreType, unsigned char* pPin, int nPin, char* pCertPath, int nCertPathlen, unsigned char* pOldPasswd, int nOldPasswdlen, unsigned char* pNewPasswd, int nNewPasswdlen);

/**
 * @brief   : ������ ��� ��ȣ ����(��ȣ�� ������ ����� ���� ��ȣ�����Ѵ�.)
 * @param	: [IN] int nStoreType				[ ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  ���� ]
 * @param   : [IN] int nPin 					[ PIN ������ ���� ]
 * @param	: [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param   : [IN] int nCertPathlen				[ ������ ��� ���� ]
 * @param	: [OUT]unsigned char* pOldPasswd	[ ���� ��� ��ȣ ]
 * @param	: [OUT]int nOldPasswdlen			[ ���� ��� ��ȣ ���� ]
 * @param	: [OUT]unsigned char* pNewPasswd	[ ���ο� ��� ��ȣ ]
 * @param	: [OUT]int nNewPasswdlen			[ ���ο� ��� ��ȣ ���� ] 
 */
INISAFEXSAFE_API int IXL_Set_CertChange_PasswordEx(int nStoreType, unsigned char* pPin, int nPin, char* pECertPath, int nECertPathlen, unsigned char* pOldPasswd, int nOldPasswdlen, unsigned char* pNewPasswd, int nNewPasswdlen);

/**
 * @brief : IXL_Get_Domain_PFXFile			[ PFX(PKCS#12) ��������. ]
 * @param : [IN] int nStoreType				[ Destination ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param : [IN] char* pDomain				[ ������ ���� ]
 * @param : [IN] int nDomainlen				[ ������ ���� ���� ]
 * @param : [IN] unsigned char* pP12Path	[ P12 File ��� ]
 * @param : [IN] int nP12Pathlen			[ P12 File ��� ���� ]
 * @param : [IN] unsigned char* pSaveDrive	[ ���� ����̺� ]
 * @param : [IN] int nSaveDrivelen			[ ���� ����̺� ���� ]
 * @param : [IN] unsigned char* pDestPin	[ PIN  ���� ]
 * @param : [IN] int nDestPinlen			[ PIN ������ ���� ]
 * @param : [IN] unsigned char* pPassword	[ ��� ��ȣ ]
 * @param : [IN] int nPasswordlen			[ ��� ��ȣ ���� ]
 */
INISAFEXSAFE_API int IXL_Get_Domain_PFXFile (int nDestStoreType , char* pDomain, int nDomainlen, char* pP12tPath, int nP12Pathlen,  char* pSaveDrive, int nSaveDrivelen, unsigned char* pDestPin, int nDestPinlen, unsigned char* pPassword, int nPasswordlen);



/**
 * @brief   : PFX(PKCS#12) ��������.
 * @param	: [IN] int nStoreType				[ Destination ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pP12Path		[ P12 File ��� ]
 * @param   : [IN] int nP12Pathlen				[ P12 File ��� ���� ]
 * @param	: [IN] unsigned char* pSaveDrive	[ ���� ����̺� ]
 * @param   : [IN] int nSaveDrivelen			[ ���� ����̺� ���� ]
 * @param   : [IN] unsigned char* pDestPin		[ PIN  ���� ]
 * @param   : [IN] int nDestPinlen				[ PIN ������ ���� ]
 * @param	: [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param	: [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
 */
INISAFEXSAFE_API int IXL_Get_PFXFile (int nDestStoreType ,  char* pP12tPath, int nP12Pathlen,  char* pSaveDrive, int nSaveDrivelen, unsigned char* pDestPin, int nDestPinlen, unsigned char* pPassword, int nPasswordlen);

/**
* @brief   : PFX(PKCS#12) �����ͷ� ���� FDD�� ��������(����������).	
* @param	: [IN] unsigned char* pP12			[ P12 ������ ]
* @param	: [IN] int nP12len					[ P12 ������ ���� ]
* @param	: [IN] unsigned char* pSaveDrive	[ ���� ����̺� ]
* @param	: [IN] unsigned char* pPassword		[ ��� ��ȣ ]
* @param	: [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
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
 * @param : [IN] unsigned char* org_data		[ ���� �� ���� ������ ]
 * @param : [IN] int org_dataLen				[ ���� �� ���� ������ ���� ]
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
 * @param : [IN] unsigned char* org_data		[ ���� �� ���� ������ ]
 * @param : [IN] int org_dataLen				[ ���� �� ���� ������ ���� ]
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
 * @brief   : �������� ����Ű�� PFX ����(PKCS#12)�� ��������.
 * @param	: [IN] int nStoreType				[ ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pPin			[ PIN  ���� ]
 * @param   : [IN] int nPin 					[ PIN ������ ���� ]
 * @param	: [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param   : [IN] int nCertPathlen				[ ������ ��� ���� ]
 * @param	: [IN] unsigned char* pSavePath		[ ���� ��� ]
 * @param   : [IN] int nSavePathlen				[ ���� ��� ���� ]
 * @param	: [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param	: [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
 */
INISAFEXSAFE_API int IXL_Set_PFXFile (int storetype, unsigned char* pPin, int nPinlen, char* pCertPath, int nCertPathlen, 
									char* pSavePath, int nSavePathlen, unsigned char* pPassword, int nPasswordlen);


/**
* @brief   : �������� ����Ű�� PFX ����(PKCS#12)�� ������ ��������.
* @param	: [IN] int nStoreType				[ ���� ��ü Type ]
*					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
* @param	: [IN] unsigned char* pCertPath		[ ������ ��� ]
* @param   : [IN] int nCertPathlen				[ ������ ��� ���� ]
* @param	: [IN] unsigned char* pPassword		[ ��� ��ȣ ]
* @param	: [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
* @param	: [OUT] unsigned char **pPKCS12		[ PKCS#12 ������ ]
* @param	: [OUT] int *pnLenP12				[ PKCS#12 ������ ���� ]
*/
INISAFEXSAFE_API int IXL_Set_PFXBuf(int storetype, char* pECertPath, int nECertPathlen, unsigned char* pPassword, int nPasswordlen, unsigned char **pPKCS12, int *pnLenP12);

/**
 * @brief   : ������ ����
 * @param	: [IN] int nSrcStoreType			[ Source ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param   : [IN] unsigned char* pSrcPin		[ Source PIN  ���� ]
 * @param   : [IN] int nsrcPinlen 				[ Source PIN ������ ���� ]
 * @param	: [IN] int nDestStoreType			[ Destination ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT
 * @param	: [IN] unsigned char* pDestDriveName[ Destination ����̺� �� ]
 * @param   : [IN] int nDestDriveNamelen		[ Destination ����̺� �� ���� ]
 * @param   : [IN] unsigned char* pDestPin		[ Destination PIN  ���� ]
 * @param   : [IN] int nDestPinlen 				[ Destination PIN ������ ���� ]
 * @param	: [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param   : [IN] int nCertPathlen				[ ������ ��� ���� ]
 * @param	: [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param   : [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
 * iOS ������
 */
INISAFEXSAFE_API int IXL_Cert_Copy (int nSrcStoreType,unsigned char* pSrcPin, int nSrcPinlen,int nDestStoreType, char* pDestDriveName,int nDestDriveNamelen,
									unsigned char* pDestPin, int nDestPinlen,  char* pCertPath,int nCertPathlen, unsigned char* pPassword,int nPasswordlen);


/**
 * @brief : IXL_Cert_Domain_Copy				[ ������ ������ ���� ]
 * @param : [IN] char* pDomain					[ ������ ���� ]
 * @param : [IN] int nDomainlen					[ ������ ���� ���� ]
 * @param : [IN] int nSrcStoreType				[ Source ���� ��ü Type ]
 * @param : [IN] unsigned char* pSrcPin			[ Source PIN  ���� ]
 * @param : [IN] int nsrcPinlen 				[ Source PIN ������ ���� ]
 * @param : [IN] int nDestStoreType				[ Destination ���� ��ü Type ]
 * @param : [IN] unsigned char* pDestDriveName	[ Destination ����̺� �� ]
 * @param : [IN] int nDestDriveNamelen			[ Destination ����̺� �� ���� ]
 * @param : [IN] unsigned char* pDestPin		[ Destination PIN  ���� ]
 * @param : [IN] int nDestPinlen 				[ Destination PIN ������ ���� ]
 * @param : [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param : [IN] int nCertPathlen				[ ������ ��� ���� ]
 * @param : [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param : [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
 */
INISAFEXSAFE_API int IXL_Cert_Domain_Copy (char* pDomain, int nDomainlen,int nSrcStoreType,unsigned char* pSrcPin, int nSrcPinlen,int nDestStoreType, char* pDestDriveName,int nDestDriveNamelen,
									unsigned char* pDestPin, int nDestPinlen, char* pCertPath,int nCertPathlen, unsigned char* pPassword,int nPasswordlen);

/**
 * @brief   : ���� Ȯ�� 
 * @param	: [IN] int nStoreType				[ ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pPin			[ PIN ���� ]
 * @param	: [IN] int nPinlen					[ PIN ���� ���� ] 
 * @param   : [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param   : [IN] int nCertPathlen				[ ������ ��� ���� ]
 * @param	: [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param   : [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
 * @param	: [IN] unsigned char* pSSN			[ �ĺ� ���� ]
 * @param	: [IN] int nSSNlen					[ �ĺ� ���� ���� ] 
*/
INISAFEXSAFE_API int IXL_Cert_Indentification (int storetype,unsigned char* pPin, int nPinlen, char* pCertPath, int nCertPathlen,unsigned char* pPassword,int nPasswrodlen,unsigned char* pSSN, int nSSNlen);

/**
 * @brief : IXL_Cert_Find					[ ������ ã��. ]
 * @param : [IN] char* pDomain				[ ������ ���� ]
 * @param : [IN] int nDomainlen				[ ������ ���� ���� ]
 * @param : [IN] unsigned char* pP12Path	[ P12 File ��� ]
 * @param : [IN] int nP12Pathlen			[ P12 File ��� ���� ]
 * @param : [IN] unsigned char* pPassword	[ ��� ��ȣ ]
 * @param : [IN] int nPasswordlen			[ ��� ��ȣ ���� ]
 * @param : [OUT]unsigned char** outlist	[ ������ ���� ]
 * @param : [OUT]int* outlen				[ ������ ���� ���� ]
 */
INISAFEXSAFE_API int IXL_Cert_Find (char* pDomain, int nDomainlen, char* pP12Path, int nP12Pathlen,unsigned char* pPassword, int nPasswordlen, unsigned char** outlist, int* outlen);

/**
 * @brief   : �α��� ������ ����
 * @param	: [IN] int storetype				[ ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pPin			[ PIN ���� ]
 * @param	: [IN] int nPinlen					[ PIN ���� ���� ] 
 * @param   : [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param   : [IN] int nCertPathlen				[ ������ ��� ���� ]
 * @param	: [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param   : [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
 * @param	: [IN] unsigned char* pOrgData		[ ���� �� ���� ������ ]
 * @param	: [IN] int nOrgDatalen				[ ���� �� ���� ������ ���� ]
 * @param	: [IN] int nEncodingFlag			[ OutPut Data�� Encoding ����]
 *				(0)  Encoding ���� , (1)  Base64 Encoding
 * @param	: [OUT]unsigned char** pDerCert		[ DER Type�� ������, Base64 Encoding ]
 * @param	: [OUT]int* nDerCertlen				[ DER Type�� ������ ���� ] 
 * @param	: [OUT]unsigned char** pSignData	[ ������ ������  ]
 * @param	: [OUT]int* nSignDatalen			[ ������ ������ ���� ] 
 * @param	: [OUT]unsigned char** pRandom		[ 'R' ������  ]
 * @param	: [OUT]int* nRandomlen				[ 'R' ������ ���� ] 
 * @param	: [OUT]unsigned char** pPadding		[ Padding Mode ]
 * @param	: [OUT]int* nPaddinglen				[ Padding Mode ���� ] 
 * @param	: [OUT]unsigned char** pHash_alg	[ Hash �˰���  ]
 * @param	: [OUT]int* nHash_alg				[ Hash �˰��� ���� ] 
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
 * @brief   : ���� ��ü ������ ����
 * @param	: [IN] int storetype				[ ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pPin			[ PIN ���� ]
 * @param	: [IN] int nPinlen					[ PIN ���� ���� ] 
 * @param   : [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param   : [IN] int nCertPathlen				[ ������ ��� ���� ]
 * @param	: [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param   : [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
 * @param	: [IN] unsigned char* pOrgData		[ ���� �� ���� ������ ]
 * @param	: [IN] int nOrgDatalen				[ ���� �� ���� ������ ���� ]
 * @param	: [IN] int nEncodingFlag			[ OutPut Data�� Encoding ����]
 *				(0)  Encoding ���� , (1)  Base64 Encoding
 * @param	: [OUT]unsigned char** pDerCert		[ DER Type�� ������, Base64 Encoding ]
 * @param	: [OUT]int* nDerCertlen				[ DER Type�� ������ ���� ] 
 * @param	: [OUT]unsigned char** pSignData	[ ������ ������  ]
 * @param	: [OUT]int* nSignDatalen			[ ������ ������ ���� ] 
 * @param	: [OUT]unsigned char** pRandom		[ 'R' ������  ]
 * @param	: [OUT]int* nRandomlen				[ 'R' ������ ���� ] 
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
 * @brief   : ������ �߱�.
 * @param	: [IN] int nStoreType				[ �߱޵� �������� ����� ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pDriveName	[ ����̺�� , ( 'C:' ���� ) ]
 * @param   : [IN] int nDriveNamelen			[ ����̺�� ���� ]
 * @param	: [IN] unsigned char* pPIN			[ PIN ]
 * @param   : [IN] int nPINlen					[ PIN ���� ]
 * @param   : [IN] unsigned char* pCAName		[ �߱��� ��û�� CA ��Ī ]
 * @param   : [IN] int nCANamelen				[ �߱��� ��û�� CA ��Ī ���� ]
 * @param	: [IN] unsigned char* pCAIP			[ CAIP ]
 * @param	: [IN] int nCAIPlen					[ CAIP ���� ]
 * @param	: [IN] unsigned char* pCAPort		[ CAPort ]
 * @param	: [IN] int nCAPortlen				[ CAPort ���� ]
 * @param	: [IN] unsigned char* pNeonCAName	[ �缳 CA Name ]
 * @param	: [IN] int nNeonCANamelen			[ �缳 CA Name ���� ]
 * @param	: [IN] unsigned char* pNeomCAPath	[ �缳 CA ��� ]
 * @param	: [IN] int nNeomCAPathlen			[ �缳 CA ��� ���� ]
 * @param	: [IN] unsigned char* pRef			[ ���� ��ȣ ]
 * @param	: [IN] int nReflen					[ ���� ��ȣ ���� ]
 * @param	: [IN] unsigned char* pAuthCode		[ �ΰ� ��ȣ ]
 * @param	: [IN] int nAuthcodelen				[ �ΰ� ��ȣ ���� ]
 * @param	: [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param	: [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
 * @param	: [IN] unsigned char* pHashAlg		[ �ؽ� �˰��� ]
 * @param	: [IN] int nReflen					[ �ؽ� �˰��� ���� ]
 * @param	: [IN] unsigned char* pKeyBit		[ Key ���� ]
 * @param	: [IN] int nKeyBitlen				[ Key ���� ]
 */
INISAFEXSAFE_API int IXL_Issue_Certificate (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,  char* pCAIP, int nCAIPlen , char* pCAPort, int nCAPortlen,
							 unsigned char* pNeonCAName , int nNeonCANamelen, unsigned char* pNeonCAPath, int nNeonCAPathlen,unsigned char* pRefVal, int nRefVallen, unsigned char* pAuthCode, int nAuthCodelen, unsigned char* pPassword, int nPasswordlen, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);



/**
 * @brief   : ������ ��߱�.
 * @param	: [IN] int nStoreType				[ ��߱޵� �������� ����� ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pDriveName	[ ����̺�� , ( 'C:' ���� ) ]
 * @param   : [IN] int nDriveNamelen			[ ����̺�� ���� ]
 * @param	: [IN] unsigned char* pPIN			[ PIN ]
 * @param   : [IN] int nPINlen					[ PIN ���� ]
 * @param   : [IN] unsigned char* pCAName		[ ��߱��� ��û�� CA ��Ī ]
 * @param   : [IN] int nCANamelen				[ ��߱��� ��û�� CA ��Ī ���� ]
 * @param	: [IN] unsigned char* pCAIP			[ CAIP ]
 * @param	: [IN] int nCAIPlen					[ CAIP ���� ]
 * @param	: [IN] unsigned char* pCAPort		[ CAPort ]
 * @param	: [IN] int nCAPortlen				[ CAPort ���� ]
 * @param	: [IN] unsigned char* pNeonCAName	[ �缳 CA Name ]
 * @param	: [IN] int nNeonCANamelen			[ �缳 CA Name ���� ]
 * @param	: [IN] unsigned char* pNeomCAPath	[ �缳 CA ��� ]
 * @param	: [IN] int nNeomCAPathlen			[ �缳 CA ��� ���� ]
 * @param	: [IN] unsigned char* pRef			[ ���� ��ȣ ]
 * @param	: [IN] int nReflen					[ ���� ��ȣ ���� ]
 * @param	: [IN] unsigned char* pAuthCode		[ �ΰ� ��ȣ ]
 * @param	: [IN] int nAuthcodelen				[ �ΰ� ��ȣ ���� ]
 * @param	: [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param	: [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
 * @param	: [IN] unsigned char* pHashAlg		[ �ؽ� �˰��� ]
 * @param	: [IN] int nReflen					[ �ؽ� �˰��� ���� ]
 * @param	: [IN] unsigned char* pKeyBit		[ Key ���� ]
 * @param	: [IN] int nKeyBitlen				[ Key ���� ]
 */
INISAFEXSAFE_API int IXL_Replace_Certificate (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,  char* pCAIP, int nCAIPlen , char* pCAPort, int nCAPortlen,
							 unsigned char* pNeonCAName , int nNeonCANamelen, unsigned char* pNeonCAPath, int nNeonCAPathlen,unsigned char* pRefVal, int nRefVallen, unsigned char* pAuthCode, int nAuthCodelen, unsigned char* pPassword, int nPasswordlen, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);


/**
 * @brief : IXL_Replace_Certificate_Reduction	[ ������ ��߱� (parameter ��� )]
 * @param : [IN] int nStoreType					[ ��߱޵� �������� ����� ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param : [IN] unsigned char* pDriveName		[ ����̺�� , ( 'C:' ���� ) ]
 * @param : [IN] int nDriveNamelen				[ ����̺�� ���� ]
 * @param : [IN] unsigned char* pPIN			[ PIN ]
 * @param : [IN] int nPINlen					[ PIN ���� ]
 * @param : [IN] unsigned char* pCAName			[ ��߱��� ��û�� CA ��Ī ]
 * @param : [IN] int nCANamelen					[ ��߱��� ��û�� CA ��Ī ���� ]
 * @param : [IN] unsigned char* pDn				[ DN ]
 *											�缳�� ��� : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d&CANAME=%s&CAPATH=%s&CMD=RENEW
 *											������ ��� : REF=%s&CODE=%s&CAIP=%s&CAPORT=%d&CMD=RENEW
 * @param : [IN] int nDnlen						[ DN ���� ]
 * @param : [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param : [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
 * @param : [IN] unsigned char* pHashAlg		[ �ؽ� �˰��� ]
 * @param : [IN] int nReflen					[ �ؽ� �˰��� ���� ]
 * @param : [IN] unsigned char* pKeyBit			[ Key ���� ]
 * @param : [IN] int nKeyBitlen					[ Key ���� ]
 */
INISAFEXSAFE_API int IXL_Replace_Certificate_Reduction (int nStoreType, char* pDriveName, int nDriveNamelen, unsigned char* pPin, int nPinlen,  char* pCAName,int nCANamelen,  char* pDn, int nDnlen,
							 unsigned char* pPassword, int nPasswordlen, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);
/**
 * @brief   : ������ ����.
 * @param	: [IN] int nStoreType				[ ���ŵ� �������� ����� ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param	: [IN] unsigned char* pPIN			[ PIN ]
 * @param   : [IN] int nPINlen					[ PIN ���� ]
 * @param	: [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param   : [IN] int nCertPathlen				[ ������ ��� ���� ]
 * @param   : [IN] unsigned char* pCAName		[ �߱��� ��û�� CA ��Ī ]
 * @param   : [IN] int nCANamelen				[ �߱��� ��û�� CA ��Ī ���� ]
 * @param	: [IN] unsigned char* pCAIP			[ CAIP ]
 * @param	: [IN] int nCAIPlen					[ CAIP ���� ]
 * @param	: [IN] unsigned char* pCAPort		[ CAPort ]
 * @param	: [IN] int nCAPortlen				[ CAPort ���� ]
 * @param	: [IN] unsigned char* pNeonCAName	[ �缳 CA Name ]
 * @param	: [IN] int nNeonCANamelen			[ �缳 CA Name ���� ]
 * @param	: [IN] unsigned char* pNeomCAPath	[ �缳 CA ��� ]
 * @param	: [IN] int nNeomCAPathlen			[ �缳 CA ��� ���� ]
 * @param	: [IN] unsigned char* pOldPassword	[ ���� ��� ��ȣ ]
 * @param	: [IN] int nOldPasswordlen			[ ���� ��� ��ȣ ���� ]
 * @param	: [IN] unsigned char* pNewPassword	[ ���ο� ��� ��ȣ ]
 * @param	: [IN] int nNewPasswordlen			[ ���ο� ��� ��ȣ ���� ]
 * @param	: [IN] unsigned char* pHashAlg		[ �ؽ� �˰��� ]
 * @param	: [IN] int nReflen					[ �ؽ� �˰��� ���� ]
 * @param	: [IN] unsigned char* pKeyBit		[ Key ���� ]
 * @param	: [IN] int nKeyBitlen				[ Key ���� ]
 */
INISAFEXSAFE_API int IXL_Update_Certificate (int nStoreType,unsigned char* pPin, int nPinlen,  char* pCertPath, int nCertPathlen, char* pCAName,int nCANamelen,  char* pCAIP, int nCAIPlen , char* pCAPort, int nCAPortlen,
							unsigned char* pNeonCAName , int nNeonCANamelen, unsigned char* pNeonCAPath, int nNeonCAPathlen,unsigned char* pOldPassword, int nOldPasswordlen,unsigned char* pNewPassword, int nNewPasswordlen, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);

/**
 * @brief : IXL_Update_Certificate_Reduction	[ ������ ����(parameter ���).]
 * @param : [IN] int nStoreType					[ ���ŵ� �������� ����� ���� ��ü Type ]
 *					(0) HDD, (1) FDD, (2) SCARD, (3) USBT , (4) CA , (5) ROOT	
 * @param : [IN] unsigned char* pPIN			[ PIN ]
 * @param : [IN] int nPINlen					[ PIN ���� ]
 * @param : [IN] unsigned char* pCertPath		[ ������ ��� ]
 * @param : [IN] int nCertPathlen				[ ������ ��� ���� ]
 * @param : [IN] unsigned char* pCAName			[ �߱��� ��û�� CA ��Ī ]
 * @param : [IN] int nCANamelen					[ �߱��� ��û�� CA ��Ī ���� ]
 * @param : [IN] unsigned char* pDn				[ DN ]
 * @param : [IN] int nDnlen						[ Dn ���� ]
 * @param : [IN] unsigned char* pOldPassword	[ ���� ��� ��ȣ ]
 * @param : [IN] int nOldPasswordlen			[ ���� ��� ��ȣ ���� ]
 * @param : [IN] unsigned char* pNewPassword	[ ���ο� ��� ��ȣ ]
 * @param : [IN] int nNewPasswordlen			[ ���ο� ��� ��ȣ ���� ]
 * @param : [IN] unsigned char* pHashAlg		[ �ؽ� �˰��� ]
 * @param : [IN] int nReflen					[ �ؽ� �˰��� ���� ]
 * @param : [IN] unsigned char* pKeyBit			[ Key ���� ]
 * @param : [IN] int nKeyBitlen					[ Key ���� ]
 */
INISAFEXSAFE_API int IXL_Update_Certificate_Reduction (int nStoreType,unsigned char* pPin, int nPinlen,  char* pCertPath, int nCertPathlen, char* pCAName,int nCANamelen,  char* pDn, int nDnlen,
							unsigned char* pOldPassword, int nOldPasswordlen,unsigned char* pNewPassword, int nNewPasswordlen, char* pHashAlg, int nHashAlglen,unsigned char* pKeyBit, int nKeyBitlen);


/**
 * @brief : IXL_User_Notification			[ ���� ���� ��Ģ URL ]
 * @param : [IN] int nStoreType				[ ���� ��ü Ÿ�� ]
 * @param : [IN] unsigned char* pPin		[ PIN ]
 * @param : [IN] int nPinlen				[ PIN ���� ]
 * @param : [IN] unsigned char* pCertpath	[ ������ ��� ]
 * @param : [IN] int nCertPathlen			[ ������ ��� ���� ]
 * @param : [OUT]unsigned char** pOutData	[ ���� ���� ��Ģ URL ]
 * @param : [OUT]int nOutDatalen			[ ���� ���� ��Ģ URL ���� ]
 */
INISAFEXSAFE_API int IXL_User_Notification (int nStoreType, unsigned char* pPin, int nPinlen, char* pCertPath,int nCertPathlen, unsigned char** pOutData, int* nOutDatalen);

 /**
  *	@brief	: IXL_Log							[ INISAFEXSafe Log. ]
  *	@param	: [IN] int level					[ Log Level ]
  * @param	: [IN] char* file					[ ���� ]
  * @param	: [IN] int line						[ Line ]
  * @param	: [IN] char* format					[ ���� ]
  */
INISAFEXSAFE_API void IXL_Log(int level, char* file,int line, char* format, ...);

 /**
  *	@brief	: IXL_SetLogLevel					[ XSafe Log Level ���� ]
  *	@param	: [IN] int level					[ Log Level ]
  */
INISAFEXSAFE_API void IXL_SetLogLevel (int level);

 /**
  *	@brief	: IXL_Log_HEXA						[ XSafe Log Hexa Display ]
  */
INISAFEXSAFE_API void IXL_Log_HEXA (int level, char* file,int line,unsigned char* msgname, unsigned char* content,int len);

/**
 * @brief	: IXL_Set_DomainInfo				[ ������ ���� ���� ]
 * @param	: [IN] unsigned char* pInfo			[ ������ ����  ]
 * @param	: [IN] int nInfolen					[ ������ ���� ���� ]
 * @return
 *		���� : IXL_OK
 *		���� : Error Code
 */
INISAFEXSAFE_API int IXL_Set_DomainInfo ( char* pInfo, int nInfolen);

/**
 * @brief	: IXL_Set_DomainInfo				[ ���� ������ ���� ]
 * @param	: [IN] unsigned char* pInfo			[ ������ ����  ]
 * @param	: [IN] int nInfolen					[ ������ ���� ���� ]
 * @param	: [IN] unsigned char* pSCert		[ ���� ������  ]
 * @param	: [IN] int nSCertlen				[ ���� ������ ���� ]
 * @return
 *		���� : IXL_OK
 *		���� : Error Code
 */
INISAFEXSAFE_API int IXL_Set_ServerCert ( char* pInfo, int nInfolen,unsigned char* pSCert, int nSCertlen);

/**
 * @brief	: IXL_Delete_ServerCert				[ ���� ������ ���� ]
 * @param	: [IN] unsigned char* pInfo			[ ������ ����  ]
 * @param	: [IN] int nInfolen					[ ������ ���� ���� ]
 * @return
 *		���� : IXL_OK
 *		���� : Error Code
 */
INISAFEXSAFE_API int IXL_Delete_ServerCert (unsigned char* pInfo, int nInfolen);

/**
 * @brief	: IXL_Refresh_SessionKey			[ SessionKey ����� ]
 * @param	: [IN] unsigned char* pInfo			[ ������ ����  ]
 * @param	: [IN] int nInfolen					[ ������ ���� ���� ]
 * @return
 *		���� : IXL_OK
 *		���� : Error Code
 */
INISAFEXSAFE_API int IXL_Refresh_SessionKey (unsigned char* pInfo, int nInfolen);

/**
 * @brief	: IXL_Delete_gFilter				[ Filter ���� ���� ]
 * @param	: [IN] unsigned char* pInfo			[ ������ ����  ]
 * @param	: [IN] int nInfolen					[ ������ ���� ���� ]
 * @return
 *		���� : IXL_OK
 *		���� : Error Code
 */
INISAFEXSAFE_API int IXL_Delete_gFilter (unsigned char* pInfo, int nInfolen);

/**
 * @brief	: IXL_Delete_gFilter				[ Filter ���� ���� ]
 * @param	: [IN] unsigned char* pInfo			[ ������ ����  ]
 * @param	: [IN] int nInfolen					[ ������ ���� ���� ]
 * @return
 *		���� : IXL_OK
 *		���� : Error Code
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
 * @brief	: IXL_Make_InipluginData_vf0		[ VF0 INIPlugindata ���� ]
 * @param	: [IN] char* pDomain				[ ������ ����  ]
 * @param	: [IN] int nDomainlen				[ ������ ���� ���� ]
 * @param	: [IN] unsigned char* pData_alg		[ ALG ���� (������ �˰���)  ]
 * @param	: [IN] int nData_alglen				[ ALG ���� ���� ]
 * @param	: [IN] unsigned char* pInData		[ DT ����(��ĪŰ ��ȣȭ �� ������ )  ]
 * @param	: [IN] int nInDatalen				[ DT ���� ���� ]
 * @param	: [OUT]unsigned char** pOutData		[ VF0 INIPlugindata ]
 * @param	: [OUT]int* nOutDatalen				[ VF0 INIPlugindata ����]
 * @return
 *		���� : IXL_OK
 *		���� : Error Code
 * @remake	: 
 *		Domain �� ������ Server Cert�� ����Ű�� �̿��Ͽ� RSA ��ȣȭ�� �Ѵ�.
 *		Server�� ���Ź��� Iniplugindata �� Server Private Key�� ��ȣȭ �Ѵ�.
 */
INISAFEXSAFE_API int IXL_Make_InipluginData_VF0 (char* pDomain, int nDomainlen,char* pData_alg, 
								int nData_alglen,unsigned char* pInData, int nInDatalen, char** pOutData, int* nOutDatalen);

/**
 * @brief : IXL_Make_InipluginData_vfx0		[ VFx0 INIPlugindata ����, VF= 10 ]
 * @param : [IN] char* domain				[ ������ ����  ]
 * @param : [IN] int vf						[ Verify Flag  ]
 * @param : [IN] unsigned char* indata		[ DT ����(��ĪŰ ��ȣȭ �� ������ )  ]
 * @param : [IN] int indatal				[ DT ���� ���� ]
 * @param : [IN] unsigned char* ts			[ Time Stamp ]
 * @param : [IN] int tsl					[ Time stamp length ]
 * @param : [OUT]char** outdata				[ VF0 INIPlugindata ]
 * @param : [OUT]int* outdatal				[ VF0 INIPlugindata ����]
 */
INISAFEXSAFE_API int IXL_Make_InipluginData_VFx0 (char* domain,int vf, unsigned char* indata, int indatal,unsigned char* ts , int tsl,
								 char** outdata, int* outdatal);
/**
 * @brief : IXL_Make_InipluginData_vfx1		[ VFx1 INIPlugindata ���� ]
 * @param : [IN] int storetype				[ ���� ��ü Ÿ�� ]
 * @param : [IN] int vf						[ Verify Flag  ]
 * @param : [IN] unsigned char* pin			[ PIN ]
 * @param : [IN] int pinl					[ PIN Length ]
 * @param : [IN] char* ecertpath			[ Cert Path , Base64 Encoding ]
 * @param : [IN] unsigned char* pwd			[ Password ]
 * @param : [IN] int pwdl					[ Password Length ]
 * @param : [IN] char* domain				[ Domain Info  ]
 * @param : [IN] unsigned char* ts			[ Time Stamp ]
 * @param : [IN] int tsl					[ Time Stamp Length ]
 * @param : [IN] unsigned char* indata		[ DT ����(��ĪŰ ��ȣȭ �� ������ )  ]
 * @param : [IN] int indatal				[ DT ���� ���� ]
 * @param : [OUT]char** outdata				[ VFx1 INIPlugindata ]
 * @param : [OUT]int* outdatal				[ VFx1 INIPlugindata ����]
 */
INISAFEXSAFE_API int IXL_Make_InipluginData_VFx1 (int storetype,int vf, unsigned char* pin, int pinl, char* ecertpath,unsigned char* pwd, int pwdl,
								 char* domain,unsigned char* ts,int tsl,unsigned char* indata, int indatal,char** outdata, int* outdatal);

INISAFEXSAFE_API int IXL_Make_INIPlugindata (char* domain,int vf , int storetype,unsigned char* pin, int pinl,
                            char* Ecertpath, unsigned char* pwd, int pwdl, unsigned char* ts, int tsl,
                            unsigned char* indata, int indatal, char** outdata, int* outdatal);
								 
/**
 * @brief : IXL_Make_InipluginData_vf1			[ VF1 INIPlugindata ���� ]
 * @param : [IN] int nStoreType					[ ���� ��ü Ÿ�� ]
 * @param : [IN] unsigned char* pPin			[ PIN ]
 * @param : [IN] int nPinlen					[ PIN ���� ]
 * @param : [IN] unsigned char* pCertpath		[ ������ ��� ]
 * @param : [IN] int nCertPath					[ ������ ��� ���� ]
 * @param : [IN] unsigned char* pPassword		[ ��� ��ȣ ]
 * @param : [IN] int nPasswordlen				[ ��� ��ȣ ���� ]
 * @param : [IN] char* pDomain					[ ������ ����  ]
 * @param : [IN] int nDomainlen					[ ������ ���� ���� ]
 * @param : [IN] unsigned char* pVd				[ ���� �ð� URL ]
 * @param : [IN] int nVdlen						[ ���� �ð� URL ���� ]
 * @param : [IN] unsigned char* pData_alg		[ ALG ���� (������ �˰���)  ]
 * @param : [IN] int nData_alglen				[ ALG ���� ���� ]
 * @param : [IN] unsigned char* pDt				[ DT ����(��ĪŰ ��ȣȭ �� ������ )  ]
 * @param : [IN] int nDtlen						[ DT ���� ���� ]
 * @param : [IN] unsigned char* pSign_Padding	[ ���� Pad Mode ]
 * @param : [IN] unsigned char* pSign_alg		[ ���� �˰��� ]
 * @param : [OUT]unsigned char** pOutData		[ VF1 INIPlugindata ]
 * @param : [OUT]int* nOutDatalen				[ VF1 INIPlugindata ����]
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
 * @brief	: IXL_SYM_Decrypt					[ ��ĪŰ ��ȣȭ ]
 * @param	: [IN] unsigned char* pDomain		[ ������ ���� ]
 * @param	: [IN] int nDomainlen				[ ������ ���� ���� ]
 * @param	: [IN] unsigned char* pData_alg		[ ��ĪŰ ��ȣȭ �˰��� ]
 * @param	: [IN] int nData_alglen				[ ��ĪŰ ��ȣȭ �˰��� ���� ]
 * @param	: [IN] unsigned char* pDt			[ ��ȣȭ�� ������ (Base64&URL encoding) ]
 * @param	: [IN] int nDtlen					[ ��ȣȭ�� ������ (Base64&URL encoding) ���� ]
 * @param	: [OUT]unsigned char** pOutData		[ ��ȣȭ �� ������ ]
 * @param	: [OUT]int* nOutDatalen				[ ��ȣȭ �� ������ ����]
 * @return
 *		���� : IXL_OK
 *		���� : Error Code
 */
 INISAFEXSAFE_API int IXL_SYM_Decrypt (unsigned char* pDomain , int nDomainlen,unsigned char* pData_alg, int nData_alglen, 
	                                   unsigned char* pDt, int nDtlen,unsigned char** pOutData,int* nOutDatalen);
/**
 * @brief :	IXL_CertPath_CRL					[������ ��θ� �̿��Ͽ� ������ ��ȿ�� �����ϱ� ]
 * @param : [IN] unsigned char* pCertPath		[������ ���]
 * @param : [IN] int nCertPathlen				[������ ��� ����]
 */
INISAFEXSAFE_API int IXL_CertPath_CRL ( char* pCertPath, int nCertPathlen);


/**
 * @brief	: IXL_Set_Property					[ �Ӽ� ���� ]
 * @param	: [IN] char* pDomain				[ ������ ���� ]
 * @param	: [IN] int nDomainlen				[ ������ ���� ����]
 * @param	: [IN] unsigned char* pFieldName	[ �ʵ� ���� ]
 * @param	: [IN] int nFieldNamelen			[ �ʵ� ���� ���� ]
 * @param	: [IN] unsigned char* pValue		[ �ʵ忡 �ش��ϴ� ����]
 * @param	: [IN] int nValuelen				[ �ʵ忡 �ش��ϴ� ���� ���� ]
 * @return
 *		���� : IXL_OK
 *		���� : Error Code
 */
INISAFEXSAFE_API int IXL_Set_Property (char* pDomain, int nDomainlen, unsigned char* pFieldName, int nFieldNamelen, unsigned char* pValue, int nValuelen);

/**
* @breif : IXL_Get_Property				[ �����ο� ������ ������ �����´�. ]
* @param : [IN] char *pDomain				[ ������ ���� ]
* @param : [IN] int nDomainlen				[ ������ ���� ���� ]
* @param : [IN] unsigned char *pFieldName	[ �����ο� ������ �ʵ� �̸� ]
* @param : [IN] int nFieldNamelen			[ �����ο� ������ �ʵ� �̸� ���� ]
* @param : [OUT]unsigned char **pOutData	[ �ʵ忡 �ش��ϴ� ���� ]
* @param : [OUT]int *nOutDatalen			[ �ʵ忡 �ش��ϴ� ���� ���� ]
*/
INISAFEXSAFE_API int IXL_Get_Property (char* pDomain, int nDomainlen, unsigned char* pFieldName,int nFieldNamelen,unsigned char** pOutData , int* nOutDatalen);

/**
 * @breif : IXL_Get_ImagePath				[ �����ο� �ش��ϴ� �̹��� ���� ��� �������� ]
 * @param : [IN] char* pDomain				[ ������ ���� ]
 * @param : [IN] int nDomainlen				[ ������ ���� ���� ]
 * @param : [OUT]unsgined char** pOutData	[ �̹��� ��� , Base64 encoding ]
 * @param : [OUT]int nOutDatalen			[ �̹��� ��� ���� ]
 */
INISAFEXSAFE_API int IXL_Get_ImagePath (char* pDomain, int nDomain,unsigned char** pOutData, int* nOutDatalen);

/**
 * @breif : IXL_Get_SessionKey				[ �����ο� �ش��ϴ� Session Key �������� ]
 * @param : [IN] char* pDomain				[ ������ ���� ]
 * @param : [IN] int nDomainlen				[ ������ ���� ���� ]
 * @param : [OUT]unsgined char** pOutData	[ Session Key , Base64 encoding ]
 * @param : [OUT]int nOutDatalen			[ Session Key ���� ]
 */
INISAFEXSAFE_API int IXL_Get_SessionKey (char* pDomain, int nDomain,unsigned char** pOutData, int* nOutDatalen);

/**
 * @brief : IXL_Get_SystemDrive				[ �ý��� ����̺� ����  ]
 * @param : [OUT]unsigned char** pOutData	[ �ý��� ����̺� ����]
 *											��) drive^C&volume^ssss
 * @param : [OUT]int* nOutDatalen			[ �ý��� ����̺� ���� ����]
 */
INISAFEXSAFE_API int IXL_Get_SystemDrive (unsigned char** pOutData, int* nOutDatalen);

/**
 * @brief : IXL_Get_DriveInfos				[ ����̺� ���� List �������� ]
 * @param : [OUT]unsigned char** pOutData	[ �ý��� ����̺� ����]
 *											��) drive^C&volume^ssss
 * @param : [OUT]int* nOutDatalen			[ �ý��� ����̺� ���� ����]
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
 * @brief : IXL_Delete_UserCert				[ ������ ��� ���� ������ ���� ]
 * @param : [IN] unsinged char* pPackage	[ ������ ���� , CA Name (����)or INITECH (�缳) ]
 * @param : [IN] int nPackagelen			[ ������ ���� ���� ]
 * @param : [IN] unsigned char* pStorage	[ ���� ��ü Type ]
 * @param : [IN] int nStoragelen			[ ���� ��ü Type ���� ]
 * @param : [IN] unsigned char* pCertValue	[ ������ ���� , �缳�� ��� ������, ������ ��� Hexa Serial number ]
 * @param : [IN] int nCertValuelen			[ ������ ���� ���� ]
 */
INISAFEXSAFE_API int IXL_Delete_UserCert(unsigned char* pPackage, int nPackagelen, unsigned char* pStorage,int nStoragelen,unsigned char* pCertValue,int nCertValuelen);

/**
 * @brief : IXL_Insert_PKCS10_Cert			[ PKCS10 ������ ���� ]
 * @param : [IN] unsigned char* pCert		[ ������ ]
 * @param : [IN] int nCertlen				[ ������ ���� ]
 */
INISAFEXSAFE_API int IXL_Insert_PKCS10_Cert (unsigned char* pCert, int nCertlen);


/**
 * @brief   : Data Encoding (Base64 or URL)
 * @param	: [IN] int nFlag						[ ���ڵ� Type, 0 : Base64 , 1: URL , 2 : BASE64 And URL]
 * @param   : [IN] unsigned char* pInData			[ �Է� ������  ]
 * @param	: [IN] int nInData						[ �Է� ������ ����]
 * @param	: [OUT]unsigned char** pOutData			[ Encoding �� ��� ������ ]
 * @param   : [OUT]int* nOutlen						[ Encoding �� ��� ������ ���� ]
 */
INISAFEXSAFE_API int IXL_DataEncode (int nFlag , unsigned char* pInData , int nInDatalen, unsigned char **pOutData, int* nOutDatalen);

/**
 * @brief   : Data Decoding (Base64 or URL)
 * @param	: [IN] int nFlag						[ ���ڵ� Type, 0 : Base64 , 1: URL , 2 : BASE64 And URL]
 * @param   : [IN] unsigned char* pInData			[ �Է� ������  ]
 * @param	: [IN] int nInData						[ �Է� ������ ����]
 * @param	: [OUT]unsigned char** pOutData			[ Decoding �� ��� ������ ]
 * @param   : [OUT]int* nOutlen						[ Decoding �� ��� ������ ���� ]
 */
INISAFEXSAFE_API int IXL_DataDecode (int nFlag , unsigned char* pInData , int nInDatalen, unsigned char **pOutData, int* nOutDatalen);

/**
 * @brief : IXL_COM_Change_Non_Proven		[ ����� ��忡�� ���� ]
 */
INISAFEXSAFE_API void IXL_COM_Change_Non_Proven ();

/**
 * @brief : IXL_Generator_Random		[ Random ���� ]
 * @param : [IN] int count				[ ������ Random Data ���� ]
 * @param : [OUT]unsigned char* out		[ Random Data ]
 */
INISAFEXSAFE_API int IXL_Generator_Random (int count, unsigned char** out);

/**
 * @brief : IXL_Symmetric_Crypto		[ ��ĪŰ ��ȣȭ / ��ȣȭ ]
 * @param : [IN] encrypt_flag			[ 1: ��ȣȭ , 1�̿��� ��� ��ȣȭ  ]
 * @param : [IN] unsigned char* key		[ Session Key ]
 * @param : [IN] int keyl				[ Session key length ]
 * @param : [IN] unsigned char* iv		[ Initial Vector ]
 * @param : [IN] int ivl				[ Initial Vector length ]
 * @param : [IN] char* alg				[ ������ �˰��� (ex)"SEED-CBC"]
 * @param : [IN] int pad_mode			[ Padding mode ]
 *										ICL_PKCS5_PAD	0x01
 * @param : [IN] char encode_flag		[ ��� �������� Encoding/Decoding ���� ]
 *										ICL_NO_ENCODE		0x10	No encoding flag 
 *										ICL_B64_ENCODE		0x00	Base64 encoding flag 
 *										ICL_B64_LF_ENCODE	0x01	Base64 encoding with 'insert linefeed' flag	
 * @param : [IN] unsigned char* indata	[ �Է� ������ ]
 * @param : [IN] int indatal			[ �Է� ������ ���� ]					
 * @param : [OUT]unsgined char** outdata[ ��ȣȭ / ��ȣȭ�� ������ ]
 * @param : [OUT]int* outdatal			[ ��ȣȭ / ��ȣȭ�� ������ ���� ]
 */ 
INISAFEXSAFE_API int IXL_Symmetric_Crypto (int encrypt_flag,unsigned char* key, int keyl , unsigned char* iv, int ivl,char* alg,int pad_mode,
										   char encode_flag,unsigned char* indata,int indatal,unsigned char** outdata,int*outdatal);


/**
 * @brief : IXL_RSA_Public_Crypto		[ ����Ű(������)�� �̿��Ͽ� RSA ��ȣȭ / ��ȣȭ ]
 * @param : [IN] encrypt_flag			[ 1: ��ȣȭ , 1�̿��� ��� ��ȣȭ  ]
 * @param : [IN] unsigned char* key		[ public Key or cert ]
 * @param : [IN] int keyl				[ public Key or cert length ]
 * @param : [IN] int pad_mode			[ Padding mode ]
 *										ICL_RSAES_PKCS1_15			0x20 RSA encryption PKCS1 v1.5 ENCODE
 *										ICL_RSAES_OAEP_20			0x08 RSA encryption OAEP v2.0 ENCODE
 *										ICL_RSAES_OAEP_21			0x10 RSA encryption OAEP v2.1 ENCODE
 * @param : [IN] char encode_flag		[ ��� �������� Encoding/Decoding ���� ]
 *										ICL_NO_ENCODE		0x10	No encoding flag 
 *										ICL_B64_ENCODE		0x00	Base64 encoding flag 
 *										ICL_B64_LF_ENCODE	0x01	Base64 encoding with 'insert linefeed' flag	
 * @param : [IN]char* hash_alg			[ Hash Algorithm Name (ex) "SHA256" , (SHA1 | SHA256 | SHA512 | HAS160) ]
 * @param : [IN] unsigned char* indata	[ �Է� ������ ]
 * @param : [IN] int indatal			[ �Է� ������ ���� ]					
 * @param : [OUT]unsgined char** outdata[ ��ȣȭ / ��ȣȭ�� ������ ]
 * @param : [OUT]int* outdatal			[ ��ȣȭ / ��ȣȭ�� ������ ���� ]
 */
INISAFEXSAFE_API int IXL_RSA_Public_Crypto (int encrypt_flag,unsigned char* cert, int certl , char pad_mode,char encode_flag,
											char* hash_alg,unsigned char* indata,int indatal, unsigned char** outdata,int* outdatal);



/**
 * @brief : IXL_RSA_Public_Verify			[ ����Ű or �������� �̿��Ͽ� ���� ����]
 * @param : [IN] unsigned char* cert		[ public Key or cert]
 * @param : [IN] int certl					[ public Key or cert length ]
 * @param : [IN] int pad_mode				[ Padding mode ]
 *											ICL_NO_PAD				0x00
 *											ICL_RSASSA_PKCS1_15		0x01 RSA signature PKCS1 v1.5 ENCODE
 *											ICL_RSASSA_PSS			0x02 RSA signature PSS ENCODE
 * @param : [IN] char encode_flag			[ ��� �������� Encoding/Decoding ���� ]
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
 * @brief : IXL_Get_ValueOfX509Field		[ �������� X509������ �������� ��ȯ�Ͽ� X509 �����͸� �����´� ]
 * @param : [IN] unsigned char* cert		[ cert ]
 * @param : [IN] int certl					[ cert length ]
 * @param : [IN] char* name					[ X509 struct�� ��� name ]
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
 * @param : [OUT]unsigned char** outdata	[ name�� �ش��ϴ� value ]
 * @param : [OUT]int* outdatal				[ name�� �ش��ϴ� value Length ]
 */
INISAFEXSAFE_API int IXL_Get_ValueOfX509Field (unsigned char* cert , int certl , char* name, unsigned char** outdata, int* outdatal);

/**
 * @brief : IXL_Verify_signature			[ CA Cert�� �̿��Ͽ� User Cert ���� ���� ]
 * @param : [IN] unsigned char* cert		[ cert ]
 * @param : [IN] int certl					[ cert length ]
 * @param : [IN] unsigned char* cacert		[ CA Cert ]
 * @param : [IN] int cacertl				[ Length of CA Cert ]
 * @return
 *			0 : success , -1 : fail
 */
INISAFEXSAFE_API int IXL_Verify_signature (unsigned char* cert , int certl , unsigned char* cacert, int cacertl);

/**
 * @brief : IXL_Cert_Verify_Validity		[ Cert ��ȿ�� Check ]
 * @param : [IN] unsigned char* cert		[ cert ]
 * @param : [IN] int certl					[ cert length ]
 * @return
 *			0 : success , -1 : fail
 */
INISAFEXSAFE_API int IXL_Cert_Verify_Validity (unsigned char* cert, int certl);

/**
 * @brief : IXL_ServerCert_Verify_Validity	[ Scert ��ȿ�� Check ]
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
 * @brief : IXL_GetSystemVersion			[ �ý��� ���� ��� ( Wind �� ) ]
 * @return
 *		Fail 	(-1)
 */
INISAFEXSAFE_API int IXL_GetSystemVersion ();

/**
 * @brief : IXL_Set_HSM_Drive					[ ����� ���� ��ū ������ ]
 * @param : [IN] char* pDomain					[ ������ ���� ]
 * @param : [IN] int nDomainlen					[ ������ ���� ���� ]
 * @param : [IN] unsigned char* pUSBTModule		[ ���� ��ū ���  ex: "C:\\WINDOWS\\system32\\eTPKCS11.dll"]
 * @param : [IN] int nUSBTModulelen				[ ���� ��ū ��� ���� ]
 * @return
 *			���� : IXL_OK
 *			���� : Error code
 */
INISAFEXSAFE_API int IXL_Set_HSM_Drive (char* pDomain, int nDomainlen,unsigned char* pHSMModule, int nHSMModulelen);

/**
 * @brief : IXL_HSM_Status						[ ���� ��ū ���� Check ]
 * @param : [IN] unsigned char* pInHSMUrl		[ ���� ��ū ���� Check�� ���� URL �ּ� ]
 * @param : [IN] int nInHSMUrllen				[ ���� ��ū ���� Check�� ���� URL �ּ� ���� ]
 * @param : [OUT]unsigned char** pOutdata		[ ���� ��ū ���� ����� ]
 *												[ ���� ��� ���� X , ����̹� ��ġ X : URL �ּ�]
 *												[ ���� ��ū ���� O , ����̹� ��ġ O : ���� ��ū ����]
 *												[ ���� ��ū ���� : ���� ��ū �̸�&����&����̹� ��ġ ����&��ġ ���]
 * @param : [OUT]int* nOutdatalen				[ ���� ��ū ���� ����� ���� ]
 * @return
 *			���� : ���� ��ū�� ���� �ǰ�, ���� ��ū ����̹��� ��ġ �Ǿ����� IXL_OK return
 *			���� : ���� ��ū�� ���� �ȵǰ�, ���� ��ū ����̹��� ��ġ ���� �ʾ����� IXL_NOK (pOutData NULL)
 *			       ���� ��ū�� ���� �ǰ�, ���� ��ū ����̹��� ��ġ ���� �ʾ�����, Error Code & pOutData ����
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
// S-PinPad�� �Լ�
#ifdef _IPHONE
/**
 * @brief : IXL_SpinKeyCleanup        [ S-Pinpad�� ����Ű �޸� ���� ]
 */
INISAFEXSAFE_API void IXL_SpinKeyCleanup(void);
    
/**
 * @brief : IXL_SpinKeyCheck        [ S-Pinpad�� ����Ű ���� ���� üũ ]
 */
INISAFEXSAFE_API int IXL_SpinKeyCheck(void);
    
/**
 * @brief : IXL_InitSpinKey                 [ S-Pinpad�� �Ϻ�ȣȭ�� ����Ű �ʱ�ȭ ]
 * @param : [IN]unsigned char* publicKey    [ S-Pinpad public key Data ]
 * @param : [IN]int publicKeyLen            [ S-Pinpad public key Length ]
 */
INISAFEXSAFE_API int IXL_InitSpinKey(unsigned char *publicKey, int publicKeyLen);

/**
 * @brief : IXL_SetSPinPublicKey        [ S-Pinpad�� �Ϻ�ȣȭ�� ����Ű �ʱ�ȭ ]
 * @param : [IN]NSString *publicKey     [ S-Pinpad public key Data ]
 */
INISAFEXSAFE_API int IXL_SetSPinPublicKey(NSString *publicKey);
    
/**
 * @brief : IXL_GetSpinkey              [ Űü�ο��� �������� S-Pinpad�� ����Ű ���� ]
 * @param : [IN] int idx                [ certificate index ]
 * @param : [OUT]unsigned char** cert   [ certificate Data ]
 * @param : [OUT]int* certlen           [ certificate Length ]
 * @param : [OUT]unsigned char** pkey   [ S-Pinpad private key Data ]
 * @param : [OUT]int* pkeylen           [ S-Pinpad private key Length ]
 */
INISAFEXSAFE_API int IXL_GetSpinkey(int idx, unsigned char **cert, int *certlen, unsigned char **pkey, int *pkeylen);
    
/**
 * @brief : IXL_Save_SPinkey                [ S-Pinpad�� ����Ű ���� ]
 * @param : [IN] int idx                    [ certificate index ]
 * @param : [IN] const char *password       [ ���� ����Ű ��й�ȣ ]
 * @param : [IN] const char *newPassword    [ S-Pinpad�� ����Ű ��й�ȣ ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Save_SPinkey (int idx, const char *password, const char *newPassword);
    
/**
 * @brief : IXL_Save_SPinkey            [ S-Pinpad�� ����Ű ���� ]
 * @param : [IN] int idx                [ certificate index ]
 * @param : [IN] NSData *password       [ ���� ����Ű ��й�ȣ ]
 * @param : [IN] NSData *newPassword    [ S-Pinpad�� ����Ű ��й�ȣ ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_Save_SPinkey (int idx, NSData *password, NSData *newPassword);
    
/**
 * @brief : IXL_DeleteSPinkey         [ S-Pinpad�� ����Ű ���� ]
 * @param : [IN] int idx            [ certificate index ]
 */
INISAFEXSAFE_API int IXL_DeleteSPinkey(int idx);
    
/**
 * @brief : IXL_FindSpinkey         [ S-Pinpad�� ����Ű ���� ���� Ȯ�� ]
 * @param : [IN] int idx            [ certificate index ]
 */
INISAFEXSAFE_API int IXL_FindSpinkey(int idx);
    
/**
 * @brief : IXL_CheckSpinkey        [ S-Pinpad�� ����Ű ��й�ȣ üũ �� ���� ���� Ȯ�� ]
 * @param : [IN] int idx            [ certificate index ]
 * @param : [IN] char *password     [ S-Pinpad�� ����Ű ��й�ȣ ]
 * @param : [IN] int passwordlen    [ S-Pinpad�� ����Ű ��й�ȣ ���� ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_CheckSpinkey(int idx, char *password, int passwordlen);
    
/**
 * @brief : IXL_CheckSpinkey        [ S-Pinpad�� ����Ű ��й�ȣ üũ �� ���� ���� Ȯ�� ]
 * @param : [IN] int idx            [ certificate index ]
 * @param : [IN] NSData *password   [ S-Pinpad�� ����Ű ��ȣȭ�� ��й�ȣ ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_CheckSpinkey(int idx, NSData* password);
    
/**
 * @brief : IXL_ChangePasswdSpinkey         [ S-Pinpad�� ����Ű ��й�ȣ ���� ]
 * @param : [IN] int idx                    [ certificate index ]
 * @param : [IN] const char* password       [ S-Pinpad�� ���� ��й�ȣ ]
 * @param : [IN] const char* newPassword    [ S-Pinpad�� �� ��й�ȣ ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_ChangePasswdSpinkey(int idx, const char* password, const char* newPassword);
    
/**
 * @brief : IXL_ChangePasswdSpinkey         [ S-Pinpad�� ����Ű ��й�ȣ ���� ]
 * @param : [IN] int idx                    [ certificate index ]
 * @param : [IN] NSData* password           [ S-Pinpad�� ��ȣȭ�� ���� ��й�ȣ ]
 * @param : [IN] NSData* newPassword        [ S-Pinpad�� ��ȣȭ�� �� ��й�ȣ ]
 */
INISAFEXSAFE_API __attribute__((overloadable)) int IXL_ChangePasswdSpinkey(int idx, NSData* password, NSData* newPassword);
    
/**
 * @brief : IXL_PKCS7_Cert_With_Random           [ PKCS#7 Sign , Cert Advanced , keypad(NFilter, S-PinPad) ����]
 * @param : [IN] int idx                         [ certificate index ]
 * @param : [IN] int nWithRandomFlag             [ OutPut Data�� WithRandom ���� ]
 *                                                  (0) WithRandom ����,   (1) WithRandom
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
 * @brief : IXL_PKCS7_Cert_With_Random           [ PKCS#7 Sign , Cert Advanced , keypad(NFilter, S-PinPad) ��ȣȭ�� ��й�ȣ ����]
 * @param : [IN] int idx                         [ certificate index ]
 * @param : [IN] int nWithRandomFlag             [ OutPut Data�� WithRandom ���� ]
 *                                                  (0) WithRandom ����,   (1) WithRandom
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
    
#define SPINPAD_DECRYPT_FAIL                    1053021        // S-Pinpad�� ��ȣ�� ��й�ȣ ��ȣȭ ����
#define GET_SPINPAD_PUBKEY_FAIL                 1053022        // S-Pinpad�� ��й�ȣ ��/��ȣ ����Ű�� ����
#define NOT_EXIST_SPINPADKEY                    1053023        // S-Pinpad�� ����Ű�� Űü�ο� ����
#define SPINPADKEY_PASSWORD_INCORRECT           1053024        // S-Pinpad�� ����Ű ��й�ȣ Ʋ��
#define SPINPADKEY_COPY_SAVE_FAIL               1053025        // S-Pinpad�� ����Ű ���� ����
#define PASSWORD_CHANGED_SPINPADKEY_SAVE_FAIL   1053026        // S-Pinpad�� ����Ű ��й�ȣ ���� ����
#define GET_CERTSPINPADKEY_FROM_IOS_FAIL        1053027        // S-Pinpad�� ����Ű ���� ����
#define FAIL_DELETE_SPINKEY_IPHONE_KEYCHAIN     1053028        // S-Pinpad�� ����Ű ���� ����

#define BASE64_DECODING_ERROR                   1053030
    


#define MSG_OPENDIR_ERROR					"Directory open ����"
#define MSG_GETALLCERTHEADER_PARAM_ERROR	"����������Ʈ �������� ����. path Ȯ��"
#define MSG_LISTSTR_MALLOC_FAIL				"������ ����Ʈ ��Ʈ�� �������� ����. �޸��Ҵ� ����"
#define MSG_CERT_INFO_MEMALLOC_ERROR		"������ �������� ����ü ���� ����."
#define MSG_GETSERIAL_X509_ERROR			"���������� Serial Number �������� ����."
#define MSG_X509GETSUBJECTDN_PARAM_ERROR	"���������� SubjectDN�� �������µ� ����. ������ �Ķ���Ͱ� ��"
#define MSG_X509GETSUBJECTNAME_ERROR		"���������� SubjectName�� �������µ� ����."
#define MSG_SKINFO_MALLOC_ERROR				"SKID ����ü ���� ����."
#define MSG_ENVELOPED_ENC_WITHSKEYIV_BASE64_ERROR	"Enveloped Encrypt (skey,iv����) ����"
#define MSG_CERT_DIGEST_ERROR				"SKID �迭�ʱ�ȭ �ϴ��� �������� �ؽ��ϴµ� ����"
#define MSG_SYMENCRYPT_ERROR				"��ĪŰ ��ȣȭ ����"
#define MSG_SYMDECRYPT_ERROR				"��ĪŰ ��ȣȭ ����"
#define MSG_BUFFER_OVERFLOW_ERROR			"���� �����÷ο� ����"
#define MSG_INITSKIDARRAY_PARAM_ERROR		"SKID ����ü �迭 Init ����. �Ķ���� Ȯ��"
#define MSG_GETSKEYIV_PARAM_ERROR			"����Ű IV �������� ����. �Ķ���� SKID NULL"
#define MSG_NOTFOUND_SKID_ERROR				"ã�����ϴ� SKID�� ����Ǿ����� ����."
#define MSG_ENVELOPED_DEC_WITHSKEYIV_ERROR	"����Ű�� IV ���� Enveloped Decrypt ����"
#define MSG_ADDSKEYIV_PARAM_ERROR			"����Ű�� IV ���� ����. ��������Ʈ���� NULL"
#define MSG_ENVELOPED_ENC_PARAM_ERROR		"Enveloped Encrypt ����. �Ķ���� skid�� NULL"
#define MSG_SYMENCRYPT_PARAM_ERROR			"��ĪŰ ��ȣȭ ����. �Ķ���� skid�� NULL"
#define MSG_SYMENCRYPT_GETSKEYIV_ERROR		"��ĪŰ ��ȣȭ ����. skid �� ��Ī�Ǵ� ����Ű IV�� ã���� ����."
#define MSG_IXL_UNKNOWN_ERROR				"���ǵ��� ���� ���� �޽��� �Դϴ�."

#define MSG_ENC_CERTANDKEY_DECRYPT_ERROR	"��ȣȭ�� ����Ű �� �������� ��ȣȭ �ϴµ� ����"
#define MSG_ENC_CERTANDKEY_PARSE_ERROR		"��ȣȭ�� ����Ű&������ �Ľ� ����"
#define MSG_IXL_MALLOC_ERROR				"�޸� �Ҵ� ����"
#define MSG_PRIVKEY_BASE64_DECODING_ERROR	"�Ľ̵� ����Ű base64 ���ڵ� ����"
#define MSG_LOAD_X509_ERROR					"X509 ���� �Ľ� ����"
#define MSG_FAIL_SAVE_TO_IPHONE_KEYCHAIN	"IPhone Keychain �� ������&Ű�� ���� ����"
#define MSG_INDEX_NOT_VALID					"��ȿ�� �ε��� ��ȣ�� �ƴմϴ�."
#define MSG_CH_PASSWORD_FAIL				"��й�ȣ ���� ����"
#define MSG_PASSWORD_CHANGED_PKEY_SAVE_FAIL	"��й�ȣ ������ �Ϸ�� ����Ű ���� ���� ����"
#define MSG_GET_RANDOM_FROM_PKEY_FAIL		"����Ű���� ���� ���� ����"
#define MSG_INVALID_VID						"VID ���� ����"
#define MSG_DELETE_FAIL_FROM_IPHONE_KEYCHAIN	"IPhone Keychain�� ������&����Ű ���� ����"
#define MSG_GET_CERTPKEY_FROM_IPHONE_FAIL	"IPhone Keychain���� ���� ����Ű&������ �������� ����"
#define MSG_PKEY_READ_ERROR					"�ε��� ��° ����Ű�� �ϵ��ũ�� ���� �о���� ����"
#define MSG_PKEY_PASSWORD_INCORRECT			"����Ű ��й�ȣ Ʋ��"
#define MSG_CHECKVID_PARAM_ERROR			"VID ���� �Ķ���� ����"
#define MSG_CHECKPOP_PARAM_ERROR			"����Ű ��й�ȣ ���� �Ķ���� ����"
#define MSG_DECRYPT_ERROR					"������ ��ȣȭ ����: �ֹι�ȣ, ������ȣ �Է� Ȯ��"
#define MSG_SETINIPLUGINPROPERTY_PARAM_ERROR		"iniplugindata property set parameter error"
#define MSG_SID_NULL								"sid is null"
#define MSG_MAKEINIPLUGINDATA_PARAM_ERROR			"MakeINIPluginData Parameter error"
#define MSG_IPDECRYPT_PARAM_ERROR					"IPDecrypt Parameter error"	
	
/* manwoo.cho add */
#define MSG_DLL_LOAD_ERROR					"DLL �ε� ����"
#define MSG_DLL_GET_FUNCTION_ERROR			"DLL �Լ� ȣ�� ����"
#define MSG_FAIL_TO_VERIFY_INDATA           "�̹��� ���� ����" 
#define MSG_VIERIFY_INDATA_PARAM_ERROR		"�̹��� ���� ������ ����"
#define MSG_VIERIFY_ORG_DATA_LEN_ERROR		"�̹��� ���� ���� ������ ���� ����"
#define MSG_MEMORY_ALLOCATE_ERROR			"�޸� �Ҵ� ����"
#define MSG_PIN_PARAMETER_ERROR				"PIN �Ķ���� ���� & PIN ���� ����"
#define MSG_PATH_PARAMETER_ERROR			"��� �Ķ���� ���� & ��� ���� ����"
#define MSG_PATH_AND_LEN_ERROR				"Path �����Ϳ� Path ���� ������ ��ġ���� �ʴ´�."
#define MSG_IXL_INVALID_ARGUMENT_ERROR		"�Է� �Ķ���� ���� "
#define MSG_DATA_HASH_ERROR					"�Է� �����͸� Hash�ϴ� ���� ���� �߻�"
#define MSG_INVALID_PASSWORD_ERROR			"�Է� ��� ��ȣ ����"
#define MSG_INVALID_CERT_ERROR				"�������� �ʴ� ������ Type"
#define MSG_INVALID_DATA_ERROR				"������ ����"
#define MSG_CA_NAME_PARAMETER_ERROR			"CA Name �Ķ���� ����"
#define MSG_CA_IP_PARAMETER_ERROR			"CA IP �Ķ���� ����"
#define MSG_CA_Port_PARAMETER_ERROR			"CA Port �Ķ���� ����"
#define MSG_CA_URL_PARAMETER_ERROR			"CA URL �Ķ���� ����"
#define MSG_CA_URLPATH_PARAMETER_ERROR		"CA URL Path �Ķ���� ����"
#define MSG_REF_VAL_PARAMETER_ERROR			"���� �ڵ� �Ķ���� ����"
#define MSG_AUTH_CODE_PARAMETER_ERROR		"�ΰ� �ڵ� �Ķ���� ����"
#define MSG_CMP_ISSUE_CERTITICATE_ERROR		"CMP LIB ������ �߱� ����"
#define MSG_CMP_REPLACE_CERTITICATE_ERROR	"CMP LIB ������ ��߱� ����"
#define MSG_CMP_UPDATE_CERTITICATE_ERROR	"CMP LIB ������ ���� ����"
#define MSG_FILTER_TYPE_ERROR				"���� ���� ���� Filter Type"
#define MSG_DRIVE_NAME_ERROR				"����̺� ���� ��Ȯ���� �ʽ��ϴ�."
#define MSG_ORIGINAL_SIGN_DATA_ERROR		"������ ���� ���� ������ ����"
#define MSG_SSN_DATA_ERROR					"�ĺ� ���� ����"
#define MSG_READ_FILE_ERROR					"���� �о���� ����"
#define MSG_WRITE_FILE_ERROR				"���� ���� ����"
#define MSG_X509_CERT2DER_ERROR				"Cert to DER ��ȯ ����"
#define MSG_PK1_SIGN_ERROR					"�α���(PKCS#1) ���� ����"
#define MSG_PK7_SIGN_ERROR					"��ü(PKCS#7) ���� ����"
#define MSG_GET_PK12_ERROR					"PKCS#12 �������� ����"
#define MSG_SET_PK12_ERROR					"PKCS#12 �������� ����"
#define MSG_RANDOM_DATA_ERROR				"Random Data ����"
#define MSG_GEN_SESSIONKEY_ERROR			"SessionKey ���� ����"
#define MSG_DOMAIN_INFO_ERROR				"������ ���� ����"
#define MSG_CTX_NULL						"CTX ����ü NULL"
#define MSG_SERVER_CERT_EXIST				"���� ������ ������"
#define MSG_SERVER_CERT_NOT_EXIST			"���� ������ �������� ����"
#define MSG_IXL_OK							"����"
#define MSG_IXL_NOK							"����"
#define MSG_SESSIONKEY_EXIST				"SessionKey ������"
#define MSG_SESSIONKEY_NOT_EXIST			"SessionKey �������� ����"
#define MSG_FILTER_INFO_EXIST				"���� ������ ������"
#define MSG_FILTER_INFO_NOT_EXIST			"���� ������ �������� ����"
#define MSG_DOMAIN_NOT_FOUND				"������ ������ �������� ����"
#define MSG_IV_EXIST						"Initial Vector ���� ��"
#define MSG_IV_NOT_EXIST					"Initial Vector �������� ����"
#define MSG_PUBLICKEY_NOT_EXIST				"���� �������� ����Ű�� �������� ����"

#define MSG_SIGN_TO_BINARY_ERROR			"���� ��ū ���� DER ���� ����"
#define MSG_SERVERTIME_ERROR				"PKCS#7 ���� �ð� ����"
#define MSG_HASH_ERROR						"�ؽ� ����"
#define MSG_STATUS_NOT_SETUP_DRIVER_ERROR	"����̹��� ã�� �� ����"
#define MSG_STATUS_NOT_FOUND_STORAGE_ERROR	"��ġ�� ã�� �� ����"
#define MSG_STATUS_DRIVER_NOT_READY_ERROR	"����̹��� ��ġ �� �� ����"

#define MSG_STATUS_STORAGE_ERROR			"���� ��ū ��ġ ����"
#define MSG_STATUS_SESSION_ERROR			"���� ��ū Session ����"
#define MSG_STATUS_SIGNED_ERROR				"���� ��ū ���� ���� ����"
#define MSG_STATUS_LOGIN_ERROR				"���� ��ū �α��� ����"
#define MSG_STATUS_LOCK_ERROR				"���� ��ū�� ��� �ֽ��ϴ�."
#define MSG_HSM_MODULE_ERROR				"���� ����"

#define MSG_CERT_COPY_ERROR					"������ ���� ����"
#define MSG_CERT_REMOVE_ERROR				"������ ���� ����"
#define MSG_CERT_PKCS1_ERROR				"������ PKCS#1 ���� ����"

#define MSG_PHONE_NAME_NOT_EXIST			"�޴��� ����̹� ������ ����"
#define MSG_PHONE_URL_NOT_EXIST				"�޴��� ����̹� �ٿ�ε� URL ������ ����"
#define MSG_PHONE_VERSION_NOT_EXIST			"�޴��� ����̹� ���� ������ ����"
#define MSG_CPS_URL_NOT_FOUND				"���� ���� ��Ģ URL ������ �����ϴ�."
#define MSG_NOT_FOUND_IMAGE_PATH			"�̹��� ���� ��ΰ� �������� �ʽ��ϴ�."
#define MSG_CMP_PKCS10_ISSUE_CERTITICATE_ERROR	"CMP LIB PKCS10 ������ �߱� ����"
#define MSG_NOT_FOUND_PKCS10_STRUCT			"PKCS10 ����ü�� ã�� �� �����ϴ�"
#define MSG_INVALID_PIN_ERROR				"PIN ��ȣ ����"
#define MSG_INVALID_PIN_AND_PWD_ERROR		"PIN Ȥ�� ���ο� ��� ��ȣ ����"
#define MSG_MEMORY_CAPACITY_LACK			"HSM �޸� �뷮 ����"
#define MSG_DISCORD_DEVICETYPE				"�����ü Type ����ġ"
#define MSG_NOT_SUPPORT_DEVICE				"�������� �ʴ� ����̽�"
#define MSG_R1_VERIFY_FAIL					"R1 ���� ����"
#define MSG_INVALID_NOT_ALPHABET_PASSWORD           "������ ��й�ȣ�� ������ �ݵ�� �����ϼž� �մϴ�."
#define MSG_INVALID_EIGHT_UNDER_PASSWORD            "������ ��й�ȣ�� �ݵ�� 8�ڸ� �̻� �Է��ϼž� �մϴ�."
#define MSG_INVALID_ALL_PASSWORD					"������ ��й�ȣ�� ������ �ݵ�� �����Ͽ� 8�ڸ� �̻� �Է��ϼž� �մϴ�."

#define MSG_GET_PK12_NOT_MATCHED_PASSWORD_ERROR     "PKCS#12 �������� ���� (��й�ȣ ����ġ)"
#define MSG_GET_PK12_INVALID_PKCS12_FORMAT_ERROR    "PKCS#12 �������� ���� (PKCS12 ������ �ƴ�)"
#define MSG_GET_PK12_INVALID_ASN1_FORMAT_ERROR      "PKCS#12 �������� ���� (�߸��� ������)"

#define MSG_IXL_SPECIAL_CHARACTER_INVALID_ARGUMENT_ERROR    "������ �ʴ� Ư������ ���"
    
#define MSG_IXL_SIGN_CERT_NOT_EXIST     "����� �������� �������� ����"
    
#define MSG_INVALID_VID_LENGTH					"VID ���� �ʰ�"
    
#define MSG_BASE64_DECODING_ERROR	"base64 ���ڵ� ����"
    
#ifdef  __cplusplus
}
#endif

#endif 
