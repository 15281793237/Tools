
// HttpTestDlg.cpp : implementation file
//

#include "stdafx.h"
#include "HttpTest.h"
#include "HttpTestDlg.h"
#include "HttpToolkit.h"
#include "json/json.h"

using namespace http_toolkit;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define AUTODEL(pbuff,name)  _autoRelease (name)(pbuff)
// CAboutDlg dialog used for App About
char *g_pcertPath = NULL;

class _autoRelease
{
public:
	_autoRelease(char *pdel):pbuffer(pdel)
	{
		pwbuffer = NULL;
	}
	_autoRelease(WCHAR *pdel):pwbuffer(pdel)
	{
		pbuffer = NULL;
	}
	~_autoRelease()
	{
		if(pbuffer)
		{
			delete []pbuffer;
			pbuffer = NULL;
		}
		if(pwbuffer)
		{
			delete []pwbuffer;
			pwbuffer = NULL;
		}
	}
protected:
	char *pbuffer;
	WCHAR *pwbuffer;
};

typedef struct __headnode
{
	char *pheadData;
	__headnode *pNext;
	__headnode()
	{
		pheadData = NULL;
		pNext = NULL;
	}
}HeadNode;
class CNormalHeader:public iHeaderStrategy
{
public:
	CNormalHeader()
	{
		m_pHead = NULL;
		m_pHeadTail = NULL;
		m_pHeadCur = NULL;
		m_pCaCert = NULL;
	}
	virtual ~CNormalHeader()
	{
		m_pHeadCur = m_pHead;
		while(m_pHeadCur)
		{
			HeadNode *pnode = m_pHeadCur;
			m_pHeadCur = m_pHeadCur->pNext;
			if(pnode)
			{
				delete []pnode->pheadData;
				delete pnode;
			}
		}

	}
	virtual void AddHeader(const CString &strHeader)
	{
		char *pHead = NULL;
		CString strtmp = strHeader;
		UnicodeToUTF8(strtmp.GetBuffer(),&pHead);
		HeadNode *pnode = new HeadNode();
		pnode->pheadData = pHead;
		pnode->pNext = NULL;
		if(m_pHead == NULL)
		{
			m_pHead = pnode;
			m_pHeadTail = m_pHead;
			m_pHeadCur = m_pHead;
			return ;
		}
		else
		{
			m_pHeadTail->pNext = pnode;
			m_pHeadTail = pnode;
		}
	}
	virtual void AddHeader(const char *szUtf8Header)
	{
		int nlen = strlen(szUtf8Header);
		char *pHead = new char[nlen+1];
		pHead[nlen] = '\0';
		strcpy(pHead,szUtf8Header);
		HeadNode *pnode = new HeadNode();
		pnode->pheadData = pHead;
		pnode->pNext = NULL;
		if(m_pHead == NULL)
		{
			m_pHead = pnode;
			m_pHeadTail = m_pHead;
			m_pHeadCur = m_pHead;
			return ;
		}
		else
		{
			m_pHeadTail->pNext = pnode;
			m_pHeadTail = pnode;
		}
	}
	virtual char *next()
	{
		if(m_pHeadCur)
		{
			char* pret = m_pHeadCur->pheadData;
			m_pHeadCur = m_pHeadCur->pNext;
			return pret;
		}
		return NULL;
	}
	virtual char *GetCertPath()
	{
		return g_pcertPath;
	}

protected:
	HeadNode *m_pHead;
	HeadNode *m_pHeadTail;
	HeadNode *m_pHeadCur;
	CString m_strToken;
	char  *m_pCaCert;
};

inline CString GetAppFolder()
{
	CString strPath = _T("");
	TCHAR cPath[MAX_PATH];
	::GetCurrentDirectory(MAX_PATH,cPath);
	strPath = cPath;
	return strPath;
}

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CHttpTestDlg dialog




CHttpTestDlg::CHttpTestDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CHttpTestDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CHttpTestDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CHttpTestDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(ID_POST, &CHttpTestDlg::OnBnClickedPost)
	ON_BN_CLICKED(ID_GET, &CHttpTestDlg::OnBnClickedGet)
END_MESSAGE_MAP()


// CHttpTestDlg message handlers

BOOL CHttpTestDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	CString strPath = GetAppFolder();
	strPath += _T("\\Config.ini");
	TCHAR tBuf[256] = {0};	
	::GetPrivateProfileString(_T("SETTING"), _T("url"), _T(""), tBuf, 256, strPath);
	CString str	= tBuf;
	SetDlgItemText(IDC_EDIT1, str);

	::GetPrivateProfileString(_T("SETTING"), _T("header"), _T(""), tBuf, 256, strPath);
	str	= tBuf;
	SetDlgItemText(IDC_EDIT3, str);

	::GetPrivateProfileString(_T("SETTING"), _T("body"), _T(""), tBuf, 256, strPath);
	str	= tBuf;
	SetDlgItemText(IDC_EDIT4, str);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CHttpTestDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CHttpTestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CHttpTestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CHttpTestDlg::OnBnClickedPost()
{
	CString strPath = GetAppFolder();
	strPath += _T("\\Config.ini");
	CString strDesURL = _T("");
	GetDlgItemText(IDC_EDIT1, strDesURL);
	::WritePrivateProfileString(_T("SETTING"), _T("url"), strDesURL, strPath);
	char* pUTF8Request(NULL);
	UnicodeToUTF8((LPCWSTR)strDesURL, &pUTF8Request);
	AUTODEL(pUTF8Request,req1);
	char* pEncodedRequest(NULL);
	URLEncode(pUTF8Request, &pEncodedRequest);
	AUTODEL(pEncodedRequest,req2);

	CNormalHeader headInfo;
	CString strHeader = _T("");
	GetDlgItemText(IDC_EDIT3, strHeader);
	::WritePrivateProfileString(_T("SETTING"), _T("header"), strHeader, strPath);
	if (strHeader.Find(_T("\r\n")) != -1)
	{
		int nPos = strHeader.Find(_T("\r\n"));
		while(nPos >= 0)
		{
			CString strH = strHeader.Left(nPos);
			headInfo.AddHeader(strH);
			strHeader = strHeader.Right(strHeader.GetLength() - nPos - 2);
			nPos = strHeader.Find(_T("\r\n"));
		}
		if (!strHeader.IsEmpty())
		{
			headInfo.AddHeader(strHeader);
		}
	}
	else if (strHeader.Find(_T("\n")) != -1)
	{
		int nPos = strHeader.Find(_T("\n"));
		while(nPos >= 0)
		{
			CString strH = strHeader.Left(nPos);
			headInfo.AddHeader(strH);
			strHeader = strHeader.Right(strHeader.GetLength() - nPos - 1);
			nPos = strHeader.Find(_T("\n"));
		}
		if (!strHeader.IsEmpty())
		{
			headInfo.AddHeader(strHeader);
		}
	}
	else if (strHeader.Find(_T(";")) != -1)
	{
		int nPos = strHeader.Find(_T(";"));
		while(nPos >= 0)
		{
			CString strH = strHeader.Left(nPos);
			headInfo.AddHeader(strH);
			strHeader = strHeader.Right(strHeader.GetLength() - nPos - 1);
			nPos = strHeader.Find(_T(";"));
		}
		if (!strHeader.IsEmpty())
		{
			headInfo.AddHeader(strHeader);
		}
	}
	else
	{
		if (!strHeader.IsEmpty())
		{
			headInfo.AddHeader(strHeader);
		}
	}
	DataBlock headerData;
	DataBlock bodyData;

	char* pInfo(NULL);
	CString strBody = _T("");
	GetDlgItemText(IDC_EDIT4, strBody);
	::WritePrivateProfileString(_T("SETTING"), _T("body"), strBody, strPath);
	UnicodeToUTF8((LPCWSTR)strBody, &pInfo);
	AUTODEL(pInfo,uni4);
	PostAndRecvWithHeader(pEncodedRequest,headerData,bodyData,&headInfo,pInfo);
	WCHAR *pUniTmp(NULL);
	UTF8ToUnicode((char *)bodyData.pBuff,&pUniTmp);
	AUTODEL(pUniTmp,hd5);
	if(pUniTmp)
	{
	}
	/*json::Value my_data = json::Deserialize((char *)bodyData.pBuff);
	if (my_data.GetType() == json::NULLVal)
	{
		return ;
	}
	std::string str = my_data.ToString();*/
	std::string str = (char *)bodyData.pBuff;
	USES_CONVERSION;
	CString strData = A2W(str.c_str());
	SetDlgItemText(IDC_EDIT2, strData);
}

void CHttpTestDlg::OnBnClickedGet()
{
	CString strPath = GetAppFolder();
	strPath += _T("\\Config.ini");
	CString strDesURL = _T("");
	GetDlgItemText(IDC_EDIT1, strDesURL);
	::WritePrivateProfileString(_T("SETTING"), _T("url"), strDesURL, strPath);
	::WritePrivateProfileString(_T("SETTING"), _T("body"), _T(""), strPath);
	char* pUTF8Request(NULL);
	UnicodeToUTF8((LPCWSTR)strDesURL, &pUTF8Request);
	AUTODEL(pUTF8Request,req1);
	char* pEncodedRequest(NULL);
	URLEncode(pUTF8Request, &pEncodedRequest);
	AUTODEL(pEncodedRequest,req2);

	CNormalHeader headInfo;
	CString strHeader = _T("");
	GetDlgItemText(IDC_EDIT3, strHeader);
	::WritePrivateProfileString(_T("SETTING"), _T("header"), strHeader, strPath);
	if (strHeader.Find(_T("\r\n")) != -1)
	{
		int nPos = strHeader.Find(_T("\r\n"));
		while(nPos >= 0)
		{
			CString strH = strHeader.Left(nPos);
			headInfo.AddHeader(strH);
			strHeader = strHeader.Right(strHeader.GetLength() - nPos - 2);
			nPos = strHeader.Find(_T("\r\n"));
		}
		if (!strHeader.IsEmpty())
		{
			headInfo.AddHeader(strHeader);
		}
	}
	else if (strHeader.Find(_T("\n")) != -1)
	{
		int nPos = strHeader.Find(_T("\n"));
		while(nPos >= 0)
		{
			CString strH = strHeader.Left(nPos);
			headInfo.AddHeader(strH);
			strHeader = strHeader.Right(strHeader.GetLength() - nPos - 1);
			nPos = strHeader.Find(_T("\n"));
		}
		if (!strHeader.IsEmpty())
		{
			headInfo.AddHeader(strHeader);
		}
	}
	else if (strHeader.Find(_T(";")) != -1)
	{
		int nPos = strHeader.Find(_T(";"));
		while(nPos >= 0)
		{
			CString strH = strHeader.Left(nPos);
			headInfo.AddHeader(strH);
			strHeader = strHeader.Right(strHeader.GetLength() - nPos - 1);
			nPos = strHeader.Find(_T(";"));
		}
		if (!strHeader.IsEmpty())
		{
			headInfo.AddHeader(strHeader);
		}
	}
	else
	{
		if (!strHeader.IsEmpty())
		{
			headInfo.AddHeader(strHeader);
		}
	}
	headInfo.AddHeader(_T("Accept:application/json;charset=UTF-8"));
	DataBlock headerData;
	DataBlock bodyData;

	SendAndRecvWithHeader(pEncodedRequest,headerData, bodyData,&headInfo);

	WCHAR *pUniTmp(NULL);
	UTF8ToUnicode((char *)bodyData.pBuff,&pUniTmp);
	AUTODEL(pUniTmp,hd5);
	if(pUniTmp)
	{
	}
	/*json::Value my_data = json::Deserialize((char *)bodyData.pBuff);
	if (my_data.GetType() == json::NULLVal)
	{
		return ;
	}
	std::string str = my_data.ToString();*/
	std::string str = (char *)bodyData.pBuff;
	USES_CONVERSION;
	CString strData = A2W(str.c_str());
	SetDlgItemText(IDC_EDIT2, strData);
}
