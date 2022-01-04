
// HttpTestDlg.h : header file
//

#pragma once


// CHttpTestDlg dialog
class CHttpTestDlg : public CDialog
{
// Construction
public:
	CHttpTestDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_HTTPTEST_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedExcute();
	afx_msg void OnBnClickedPost();
	afx_msg void OnBnClickedGet();
};
