#include "StdAfx.h"
#include "HttpToolkit.h"
#include <io.h>
//#include "openssl\ssl.h"
#include "windows.h"
//#include "wincrypt.h"
//#pragma comment(lib, "Crypt32.lib")
namespace http_toolkit
{

	//////////////////////////////////////////////////////////////////////////
	/* DataBlock  */
	DataBlock::DataBlock(int nBufferSize)
	{
		nBufSize = nBufferSize;
		nPos = 0;
		pBuff = new BYTE[nBufferSize];
		memset(pBuff,0,nBufferSize);
	}

	DataBlock::~DataBlock()
	{
		delete []pBuff;
		nBufSize = 0;
		nPos = 0;
	}
	//void addCertificatesForStore(X509_STORE *certStore,const char *subSystemName)
	//{
	//	HCERTSTORE storeHandle = NULL;
	//	PCCERT_CONTEXT windowsCertificate = NULL;
	//	do 
	//	{
	//		HCERTSTORE storeHandle = CertOpenSystemStoreA(NULL, subSystemName);
	//		if (!storeHandle) {
	//			break;
	//		}
	//		while (windowsCertificate=CertEnumCertificatesInStore(storeHandle, windowsCertificate)) {
	//			X509 *opensslCertificate = d2i_X509(NULL, const_cast<unsigned char const **>(&windowsCertificate->pbCertEncoded),
	//				windowsCertificate->cbCertEncoded);
	//			if (opensslCertificate) {
	//				X509_STORE_add_cert(certStore, opensslCertificate);
	//				X509_free(opensslCertificate);
	//			}
	//		}
	//	} while (false);
	//	if (storeHandle) {
	//		CertCloseStore(storeHandle, 0);
	//	}   
	//}
	////////////////////////////////////////////////////////////////////////////
	//int sslContextFunction(void* curl, void* sslctx, void* userdata)
	//{
	//	X509_STORE *certStore = SSL_CTX_get_cert_store(reinterpret_cast<SSL_CTX *>(sslctx));
	//	if (certStore) {
	//		addCertificatesForStore(certStore, "CA");
	//		addCertificatesForStore(certStore, "AuthRoot");
	//		addCertificatesForStore(certStore, "ROOT");
	//	}
	//	return CURLE_OK;
	//}
	
	void UTF8ToUnicode(char* pUTF8Src, WCHAR** ppUnicodeDst)
	{

		int nUnicodeLen;        //转换后Unicode的长度

		//获得转换后的长度，并分配内存
		nUnicodeLen = MultiByteToWideChar(CP_UTF8,
			0,
			pUTF8Src,
			-1,
			NULL,
			0);

		nUnicodeLen += 1;
		*ppUnicodeDst = new WCHAR[nUnicodeLen];

		//转为Unicode
		MultiByteToWideChar(CP_UTF8,
			0,
			pUTF8Src,
			-1,
			*ppUnicodeDst,
			nUnicodeLen);
	}

	int UnicodeToUTF8(const WCHAR *pUnicodeSrc, char** ppUTF8Dst)
	{
		/* get output buffer length */
		int		iUTF8Len(0);
		// wide char to multi char
		iUTF8Len = WideCharToMultiByte(CP_UTF8,
			0,
			pUnicodeSrc,
			-1,
			NULL,
			0,
			NULL,
			NULL );

		/* convert unicode to UTF8 */
		iUTF8Len += 1;
		*ppUTF8Dst = new char[iUTF8Len];
		memset(*ppUTF8Dst, 0, iUTF8Len);
		iUTF8Len--;
		iUTF8Len = WideCharToMultiByte(CP_UTF8,
			0,
			pUnicodeSrc,
			-1,
			*ppUTF8Dst,
			iUTF8Len,
			NULL,
			NULL );
		return iUTF8Len;
	}

#define TOHEX(x) ((x)>9 ? (x)+55 : (x)+48)
	void URLEncode(char* szIn, char** pOut)
	{
		int nInLenth = strlen(szIn);
		int nFlag = 0;
		BYTE byte;
		*pOut = new char[nInLenth*3];
		char* szOut = *pOut;
		for (int i=0; i<nInLenth; i++)
		{
			byte = szIn[i];
			if (isalnum(byte) ||
				(byte == '-') ||  
				(byte == '_') ||   
				(byte == '.') ||   
				(byte == '~') ||
				(byte == '/') ||
				(byte == '?') ||
				(byte == ':') ||
				(byte == '=') ||
				(byte == '|') ||
				(byte == '&')) 
			{
				szOut[nFlag++] = byte;
			}
			else
			{
				if (isspace(byte))
				{
					szOut[nFlag++] = '+';
				}
				else
				{
					szOut[nFlag++] = '%';
					szOut[nFlag++] = TOHEX(byte>>4);
					szOut[nFlag++] = TOHEX(byte%16);
				}
			}
		}
		szOut[nFlag] = '\0';
	}
	void URLEncodeAll(char* szIn, char** pOut)
	{
		int nInLenth = strlen(szIn);
		int nFlag = 0;
		BYTE byte;
		*pOut = new char[nInLenth*3];
		char* szOut = *pOut;
		for (int i=0; i<nInLenth; i++)
		{
			byte = szIn[i];
			if (isalnum(byte) ||
				(byte == '-') ||  
				(byte == '_') ||   
				(byte == '.')  
				)  
			{
				szOut[nFlag++] = byte;
			}
			else
			{
				if (isspace(byte))
				{
					szOut[nFlag++] = '+';
				}
				else
				{
					szOut[nFlag++] = '%';
					szOut[nFlag++] = TOHEX(byte>>4);
					szOut[nFlag++] = TOHEX(byte%16);
				}
			}
		}
		szOut[nFlag] = '\0';
	}
	void URLEncodeSDK(CString strIn, CString &strOut)
	{
		char *ptmp = NULL; 
		int nlen = UnicodeToUTF8(strIn.GetBuffer(0),&ptmp);	
		CURL *curl = curl_easy_init();
		if(curl) {
			nlen--;//少个结束符在里面
			char *output = curl_easy_escape(curl,ptmp, nlen);
			if(output) 
			{
				USES_CONVERSION;
				strOut = A2W(output);
				curl_free(output);
			}
			curl_easy_cleanup(curl);
		}
		delete []ptmp;
	}
	static size_t write_data_to_buf(void *ptr, size_t size, size_t nmemb, void *pUserData)
	{
		DataBlock *pDataBlock = (DataBlock *)pUserData;
		//CString strdebug;
		//strdebug.Format(_T("hiveapi->curpos:%d,sizemem:%d,message:%s\n"),pDataBlock->nPos,size * nmemb,(TCHAR*)pDataBlock->pBuff);
		//OutputDebugString(strdebug);
		if (memcpy_s(pDataBlock->pBuff + pDataBlock->nPos, pDataBlock->nBufSize - pDataBlock->nPos, ptr, size * nmemb) != 0)
		{

			//TODO: error code;
			return 0;
		}

		pDataBlock->nPos += size * nmemb;
		return size * nmemb;
	}

	static size_t write_file(void *ptr, size_t size, size_t nmemb, void *pUserData)
	{
		HANDLE hFile = *((HANDLE *)pUserData);
		DWORD dwWrittenSize(0);
		::WriteFile(hFile, ptr, size * nmemb, &dwWrittenSize, NULL);

		return dwWrittenSize;
	}

	BOOL SendAndRecv(LPCSTR lpRequestUTF8Encoded, DataBlock &headerData, DataBlock &bodyData)
	{
		CURL *curl_handle;
		curl_global_init(CURL_GLOBAL_ALL);

		/* init the curl session */
		curl_handle = curl_easy_init();

//		curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT,3);   

		/* set URL to get */
		curl_easy_setopt(curl_handle, CURLOPT_URL, lpRequestUTF8Encoded);

		/* no progress meter please */
		curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);

		/* send all data to this function  */
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data_to_buf);


		/* we want the headers be written to this file handle */
		curl_easy_setopt(curl_handle,   CURLOPT_WRITEHEADER, &headerData);

		/* we want the body be written to this file handle instead of stdout */
		curl_easy_setopt(curl_handle,   CURLOPT_WRITEDATA, &bodyData);

		/* get it! */
		curl_easy_perform(curl_handle);

		/* cleanup curl stuff */
		curl_easy_cleanup(curl_handle);

		return TRUE;
	}

	BOOL SendAndRecvWithHeader(LPCSTR lpRequestUTF8Encoded,DataBlock &headerData, DataBlock &bodyData,iHeaderStrategy *pstategy)
	{
		
		CURL *curl_handle;
		curl_global_init(CURL_GLOBAL_ALL);

		/* init the curl session */
		curl_handle = curl_easy_init();

//		curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT,3);   

		/* set URL to get */
		curl_easy_setopt(curl_handle, CURLOPT_URL, lpRequestUTF8Encoded);
		curl_slist *plist1 = NULL;
		if(pstategy)
		{
			char *phead = pstategy->next();
			curl_slist *plist = curl_slist_append(NULL,phead);
			phead = pstategy->next();
			while(phead)
			{
				curl_slist_append(plist,phead);
				phead = pstategy->next();
			}
			curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, plist);
			plist1 = plist;
		}		

		/* no progress meter please */
		curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);		

		/* send all data to this function  */
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data_to_buf);


		/* we want the headers be written to this file handle */
		curl_easy_setopt(curl_handle,   CURLOPT_WRITEHEADER, &headerData);

		/* we want the body be written to this file handle instead of stdout */
		curl_easy_setopt(curl_handle,   CURLOPT_WRITEDATA, &bodyData);

		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, false);//设定为不验证证书和HOST 
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, false); 

		CURLcode nRet = CURLE_OK;
		try
		{

			/* get it! */
			nRet = curl_easy_perform(curl_handle);
			if(plist1)
				curl_slist_free_all(plist1);
			//const char *pret = curl_easy_strerror(nRet);
			/* cleanup curl stuff */
			curl_easy_cleanup(curl_handle);

		}
		catch(...)
		{
			if(plist1)
				curl_slist_free_all(plist1);

			/* cleanup curl stuff */
			curl_easy_cleanup(curl_handle);
		}
		if(nRet == CURLE_OK)
			return TRUE;
		

		return nRet;
	}

	BOOL PostAndRecvWithHeader(LPCSTR lpRequestUTF8Encoded,DataBlock &headerData, DataBlock &bodyData,iHeaderStrategy *pstategy,LPCSTR lpData)
	{
		CURL *curl_handle;
		curl_global_init(CURL_GLOBAL_ALL);

		/* init the curl session */
		curl_handle = curl_easy_init();

		//		curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT,3);   



		curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "POST");
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, lpData);



		/* set URL to get */
		curl_easy_setopt(curl_handle, CURLOPT_URL, lpRequestUTF8Encoded);
		curl_slist *plist1 = NULL;
		if(pstategy)
		{
			char *phead = pstategy->next();
			curl_slist *plist = curl_slist_append(NULL,phead);
			phead = pstategy->next();
			while(phead)
			{
				curl_slist_append(plist,phead);
				phead = pstategy->next();
			}
			curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, plist);
			plist1 = plist;
		}

		/* no progress meter please */
		curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);		

		/* send all data to this function  */
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data_to_buf);


		///* we want the headers be written to this file handle */
		curl_easy_setopt(curl_handle,   CURLOPT_WRITEHEADER, &headerData);

		///* we want the body be written to this file handle instead of stdout */
		curl_easy_setopt(curl_handle,   CURLOPT_WRITEDATA, &bodyData);

		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, false);//设定为不验证证书和HOST 
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, false); 

		/* get it! */
		CURLcode res = curl_easy_perform(curl_handle);
		BOOL bRet = FALSE;
		if(res == CURLE_OK)
			bRet = TRUE;

		if(plist1)
			curl_slist_free_all(plist1);

		/* cleanup curl stuff */
		curl_easy_cleanup(curl_handle);

		return bRet;
	}

	BOOL PutAndRecvWithHeader(LPCSTR lpRequestUTF8Encoded,DataBlock &headerData, DataBlock &bodyData,iHeaderStrategy *pstategy,LPCSTR lpData)
	{
		CURL *curl_handle;
		curl_global_init(CURL_GLOBAL_ALL);

		/* init the curl session */
		curl_handle = curl_easy_init();

		//		curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT,3);   



		curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "PUT");
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, lpData);


		curl_slist *plist1 = NULL;
		/* set URL to get */
		curl_easy_setopt(curl_handle, CURLOPT_URL, lpRequestUTF8Encoded);
		if(pstategy)
		{
			char *phead = pstategy->next();
			curl_slist *plist = curl_slist_append(NULL,phead);
			phead = pstategy->next();
			while(phead)
			{
				curl_slist_append(plist,phead);
				phead = pstategy->next();
			}
			curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, plist);
			plist1 = plist;
		}

		/* no progress meter please */
		curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);		

		/* send all data to this function  */
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data_to_buf);


		///* we want the headers be written to this file handle */
		curl_easy_setopt(curl_handle,   CURLOPT_WRITEHEADER, &headerData);

		///* we want the body be written to this file handle instead of stdout */
		curl_easy_setopt(curl_handle,   CURLOPT_WRITEDATA, &bodyData);

		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, false);//设定为不验证证书和HOST 
		curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, false); 

		/* get it! */
		CURLcode res = curl_easy_perform(curl_handle);
		BOOL bRet = FALSE;
		if(res == CURLE_OK)
			bRet = TRUE;

		if(plist1)
		curl_slist_free_all(plist1);

		/* cleanup curl stuff */
		curl_easy_cleanup(curl_handle);

		return bRet;
	}

	BOOL PostAndRecv(LPCSTR lpRequestUTF8Encoded, DataBlock &headerData, DataBlock &bodyData,LPCSTR lpData)
	{
		CURL *curl_handle;
		curl_global_init(CURL_GLOBAL_ALL);

		/* init the curl session */
		curl_handle = curl_easy_init();

		//		curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT,3);   


		CString str3=_T("Content-Type:application/json");
		char* pUTF8Header(NULL);
		UnicodeToUTF8((LPCWSTR)str3, &pUTF8Header);
		curl_slist *plist = curl_slist_append(NULL,pUTF8Header);
		curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, plist);


		curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "POST");
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, lpData);

//		curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "POST");
//		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, lpData);
//		curl_easy_setopt(curl_handle,CURLOPT_POST,1); 


		/* set URL to get */
		curl_easy_setopt(curl_handle, CURLOPT_URL, lpRequestUTF8Encoded);


		/* no progress meter please */
		curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);		

		/* send all data to this function  */
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data_to_buf);


		///* we want the headers be written to this file handle */
		curl_easy_setopt(curl_handle,   CURLOPT_WRITEHEADER, &headerData);

		///* we want the body be written to this file handle instead of stdout */
		curl_easy_setopt(curl_handle,   CURLOPT_WRITEDATA, &bodyData);

		/* get it! */
		CURLcode res = curl_easy_perform(curl_handle);
		BOOL bRet = FALSE;
		if(res == CURLE_OK)
			bRet = TRUE;


		/* cleanup curl stuff */
		curl_easy_cleanup(curl_handle);

		return bRet;
	}

	BOOL DownloadFile(LPCSTR lpRequestUTF8Encoded, LPCTSTR lpStorePath, CString &strFileName,BOOL bReplace)
	{
		CURL *curl_handle;
		curl_global_init(CURL_GLOBAL_ALL);

		/* init the curl session */
		curl_handle = curl_easy_init();

		/* set URL to get */
		curl_easy_setopt(curl_handle, CURLOPT_URL, lpRequestUTF8Encoded);

		/* no progress meter please */
		curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);

		/* send all data to this function  */
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_file);

		if (strFileName.GetLength() == 0)
		{
			WCHAR *pRequestUnicode;
			UTF8ToUnicode((char *)lpRequestUTF8Encoded, &pRequestUnicode);

			CString strRequestUnicode =  pRequestUnicode;

			int nLastSlashPos = strRequestUnicode.ReverseFind(_T('/'));

			strFileName = strRequestUnicode.Mid(nLastSlashPos + 1);

			delete []pRequestUnicode;
			pRequestUnicode = NULL;

		}


		CString strFullName(lpStorePath);
		if (strFullName.GetLength() && 
			strFullName.ReverseFind('\\') != (strFullName.GetLength()-1))
		{
			strFullName += _T('\\');
		}
		strFullName += strFileName;
		if(!bReplace)
		{
			 WIN32_FIND_DATA fileInfo; 
			 HANDLE hFind; 
			 hFind = FindFirstFile(strFullName ,&fileInfo); 
			 if(hFind != INVALID_HANDLE_VALUE && fileInfo.nFileSizeLow > 0)
			 {
				 FindClose(hFind); 
				 curl_easy_cleanup(curl_handle);
				 return TRUE;
			 }	
 		}


		/*if (_taccess(strFullName, 0) != -1)
		{
			return TRUE;
		}*/
		
		HANDLE hFile	=	::CreateFile(strFullName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);

		

//		DataBlock headerData;

		/* we want the headers be written to this file handle */
//		curl_easy_setopt(curl_handle,   CURLOPT_WRITEHEADER, &headerData);

		/* we want the body be written to this file handle instead of stdout */
		curl_easy_setopt(curl_handle,   CURLOPT_WRITEDATA, &hFile);

		/* get it! */
		CURLcode code = curl_easy_perform(curl_handle);
		int nRetry = 0;
		while (code != 0)
		{
			CString strDbg;
			strDbg.Format(L"Code=%d;Retry=%d;File:%s",code,nRetry,strFullName);
			OutputDebugString(strDbg);
			if (nRetry < 3)
			{
				Sleep(10);
				code = curl_easy_perform(curl_handle);

			}
			else 
				break;
			
			nRetry++;
		}
		

		/* cleanup curl stuff */
		curl_easy_cleanup(curl_handle);

		CloseHandle(hFile);

//		::FlushFileBuffers(hFile);
		/*DWORD dwFileSize(0);
		::GetFileSize(hFile, &dwFileSize);
		::CloseHandle(hFile);

		if (dwFileSize == 0)
		{
			::DeleteFile(strFullName);
		}*/
		return TRUE;

	}
}

