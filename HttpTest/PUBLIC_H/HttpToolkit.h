#pragma once
#include <curl/curl.h>


namespace http_toolkit
{
	class iHeaderStrategy
	{
	public:
		virtual void AddHeader(const CString &strHeader) = 0;
		virtual char *next()      = 0;
		virtual char *GetCertPath() = 0;
		virtual ~iHeaderStrategy()
		{
		}
	};
	struct DataBlock
	{
		DataBlock(int nBufferSize = 1024 * 5000);
		~DataBlock();

		BYTE* pBuff;
		int nBufSize;
		int nPos;
	};

	BOOL SendAndRecv(LPCSTR lpRequestUTF8Encoded, DataBlock &headerData, DataBlock &bodyData);
	BOOL SendAndRecvWithHeader(LPCSTR lpRequestUTF8Encoded,DataBlock &headerData, DataBlock &bodyData,iHeaderStrategy *pstategy);
	BOOL DownloadFile(LPCSTR lpRequestUTF8Encoded,  LPCTSTR lpStorePath,CString &strFileName,BOOL bReplace = FALSE);
	BOOL PutAndRecvWithHeader(LPCSTR lpRequestUTF8Encoded,DataBlock &headerData, DataBlock &bodyData,iHeaderStrategy *pstategy,LPCSTR lpData);
	BOOL PostAndRecv(LPCSTR lpRequestUTF8Encoded, DataBlock &headerData, DataBlock &bodyData,LPCSTR lpData);
	BOOL PostAndRecvWithHeader(LPCSTR lpRequestUTF8Encoded,DataBlock &headerData, DataBlock &bodyData,iHeaderStrategy *pstategy,LPCSTR lpData);


	void UTF8ToUnicode(char* pUTF8Src, WCHAR** ppUnicodeDst);
	int UnicodeToUTF8(const WCHAR *pUnicodeSrc, char** ppUTF8Dst);
	void URLEncode(char* szIn, char** pOut);
	void URLEncodeAll(char* szIn, char** pOut);
	void URLEncodeSDK(CString strIn, CString &strOut);
};

