#include "stdafx.h"
#include <windows.h>
#include <tchar.h>
#include <iostream>
using namespace std;

#ifndef ASSERT
#include <crtdbg.h>
#define ASSERT(X) _ASSERT(X);
#endif


typedef int (WINAPI* pDefaultAPI)(
	HWND hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT uType
	);


pDefaultAPI pOldAPI = NULL;            //��ָ��pOldAPI����ԭ��API�����ĵ�ַ��ͨ��GetProcAddress��ȡ��
char szOldAPI[12] = { 0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x50,0xC3 };                //�����Ϊ7�ֽڣ�szNewAPI�����unfinished
//char szNewAPI[12] = { 0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x50,0xC3 };
//char szOldAPI[7] = { 0xB8,0x00,0x00,0x00,0x00,0x50,0xC3 };
char szNewAPI[7] = { 0xB8,0x00,0x00,0x00,0x00,0x50,0xC3 };  //����ʹ���µĵ��÷�ʽ��ʹ�����������޲�������hook
char test_buf[2000] = {};
char old_api_addr[8] = {};



int WINAPI NewAPI(
	HWND hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT uType
)
{
	//Ϊ����Ϊ
	cout << "new API running,weisuoyuwei" << endl;
	WriteProcessMemory((void*)-1, pOldAPI, szOldAPI, 7, NULL);//��ԭԭ���� 
	int A = MessageBoxW(hWnd, lpText, lpCaption, uType);              //���û�ԭ���ԭ����
	WriteProcessMemory((void*)-1, pOldAPI, szNewAPI, 7, NULL);//ԭ����ִ���꣬����hook֮��
															   //Ϊ����Ϊ
	return A;
}

int injectFunc()
{
	//Ϊ����Ϊ
	cout << "new API running,weisuoyuwei" << endl;
	WriteProcessMemory((void*)-1, pOldAPI, szOldAPI, 12, NULL);//��ԭԭ���� 
	//int A = MessageBoxW(hWnd, lpText, lpCaption, uType);              //���û�ԭ���ԭ����
	WriteProcessMemory((void*)-1, pOldAPI, szNewAPI, 12, NULL);//ԭ����ִ���꣬����hook֮��
															   //Ϊ����Ϊ
	return 1;
}

bool hookapi()
{
	//�ҵ�api�������ڴ��еĵ�ַ
	pOldAPI = 0;
	//hModule hmodule = LoadLibrary(_T("kernel32.dll"));
	HMODULE hmodule = LoadLibrary(_T("user32.dll"));
	//HINSTANCE hmodule = LoadLibrary(_T("kernel32.dll"));
	pOldAPI = (pDefaultAPI)GetProcAddress(hmodule, "MessageBoxW");
	//pDefaultAPI pclosehandle = (pDefaultAPI)GetProcAddress(hmodule, "ReadFile");
	//pCloseHandleAPI pclosehandle = (pCloseHandleAPI)GetProcAddress(hmodule, "ReadFile");
	//memcpy(szOldAPI + 2, &pOldAPI, 8);
	memcpy(old_api_addr, &pOldAPI, 8);
	//memcpy(sznewcloseapi + 2, &pclosehandle, 8);
	//memcpy(szOldAPI + 2, &pclosehandle, 8);
	ASSERT(pOldAPI);
	//ASSERT(pclosehandle);
	if (!pOldAPI)
	{
		FreeLibrary(hmodule);
		return false;
	}


	//DWORD64 dwjmpaddr = 0;
	//dwjmpaddr = (DWORD64)NewAPI;
	int (WINAPI * jmpaddrp)(
		HWND hWnd,
		LPCTSTR lpText,
		LPCTSTR lpCaption,
		UINT uType
	);
	jmpaddrp = &NewAPI;
	//char addr[8] = { 0x30,0x18,0x2a ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 };

	int(*jmptestaddr)();
	jmptestaddr = &injectFunc;

	memcpy(szNewAPI + 1, &jmpaddrp, 4);
	//memcpy(szNewAPI + 2, &jmptestaddr, 4);
	ReadProcessMemory((void*)-1, pOldAPI, szOldAPI, 12, NULL);
	char a0 = szNewAPI[0];
	char a1 = szNewAPI[1];
	char a2 = szNewAPI[2];
	char a3 = szNewAPI[3];
	char a4 = szNewAPI[4];
	char a5 = szNewAPI[5];
	char a6 = szNewAPI[6];
	/*char a7 = szNewAPI[7];
	char a8 = szNewAPI[8];
	char a9 = szNewAPI[9];
	char a10 = szNewAPI[10];
	char a11 = szNewAPI[11];*/
	FreeLibrary(hmodule);
	ReadProcessMemory((void*)-1, pOldAPI, szOldAPI, 7, NULL);
	//ReadProcessMemory((void*)-1, pOldAPI, test_buf, 2000, NULL);    
	//char mboxw_addr[8] = {0x60,0x13,0x07,0x00,0x60,0x13,0xc9,0x78};

	/*int i = 0;
	for (i = 0; i < 2000; i++) {
		int j = 0;
		int has_check = 0;
		for (j = has_check; j < 8; j++) {
			if (mboxw_addr[j] == test_buf[i] && test_buf[i]!=0x00) {
				cout << "i is :" << i << "  hex:" << hex << mboxw_addr[j] << endl;
			}
		}
	}*/
	WriteProcessMemory((void*)-1, pOldAPI, szNewAPI, 7, NULL);    
	return true;
}

bool UnHookAPI()
{
	return true;
}

BOOL APIENTRY DllMain(HANDLE handle, DWORD dwReason, LPVOID reserved)
{
	HMODULE g_hThisModule = (HMODULE)handle;
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		hookapi();
		break;
	}
	case DLL_PROCESS_DETACH:
	{
		UnHookAPI();
		break;
	}
	}

	return TRUE;
}
/*
*�������Կ����Լ�hook�Լ������ִ�������main��
*��������Ҫ���ڿ���̨�����������dll������
*/

int main()
{
	hookapi();
	MessageBoxW(NULL,L"hook Messagebox", L"Test", MB_OK);
	MessageBoxW(NULL, L"hook Messagebox", L"Test", MB_OK);
}
