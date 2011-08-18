#include "stdafx.h"
#include <fstream>
#include <string>
#include "ExtList.h"

using std::wifstream;
using std::wstring;
using namespace COMSniffer;
CExtList::CExtList(void)
{
	InitializeCriticalSection(&m_cs);
}

CExtList::CExtList(WCHAR *emulist)
{
	InitializeCriticalSection(&m_cs);

	wifstream wl(emulist);
	if(!wl)
	{
#ifdef _DEBUG
		OutputDebugString(L"[CExtList::CExtList]failed to open emulist:");
		OutputDebugString(emulist);
#endif
		return;
	}

	wstring line, hookname, clsid, progid;
	while(!wl.eof())
	{
		std::getline(wl, line);
		wstring::size_type index1 = line.find_first_of(' ');
		wstring::size_type index2 = line.find_last_of(' ');
		 
		hookname = line.substr(0, index1);
		clsid = line.substr(index1 + 1, index2 - index1 - 1);
		progid = line.substr(index2 + 1);
		
		OutputDebugString(L"[CExtList::CEmulist]Add to emullist");
		OutputDebugString((clsid + L" " + progid + L" " + hookname).c_str());
#ifdef _DEBUG_VERBOSE
		OutputDebugString(L"[[ExtList]Add to emullist");
		OutputDebugString((clsid + L" " + progid).c_str());
#endif

		this->AddToExtList(hookname.c_str(), (WCHAR *)clsid.c_str(), progid.c_str());

	}

}

BOOLEAN CExtList::AddToExtList(LPCOLESTR hookname, LPOLESTR clsid_str, LPCOLESTR progid)
{
	CLSID clsid;

	if(FAILED(CLSIDFromString(clsid_str, &clsid)))
		return FALSE;
	return this->AddToExtList(hookname, clsid, progid);
}
/// This function is to add a new item into the list
/// The list is list<REFCLSID rclsid, BSTR progid>
BOOLEAN CExtList::AddToExtList(LPCOLESTR hookname, REFCLSID rclsid, LPCOLESTR progid)
{
	BSTR m_progid, m_hookname;
	// 0. convert the type of progid
	m_progid = ::SysAllocString(progid);
	if(!m_progid)
		return FALSE;
	m_hookname = ::SysAllocString(hookname);
	if(!m_hookname)
		return FALSE;
	// 1. new an ExtListItem
	ExtListItem *item = new ExtListItem(m_hookname, rclsid, m_progid);
	if(!item)
		return FALSE;

	// 2. push the item into the list
	EnterCriticalSection(&m_cs);
	m_list.push_back(item);
	LeaveCriticalSection(&m_cs);
	return TRUE;
}

BOOLEAN CExtList::IsInExtList(REFCLSID rclsid)
{
#ifdef _DEBUG_VERBOSE
	LPOLESTR clsid;
	StringFromCLSID(rclsid, &clsid);
	OutputDebugString(L"CAvailableList::IsInAvailableList");
	OutputDebugString(clsid);
	CoTaskMemFree(clsid);
#endif

	BOOLEAN bFound = FALSE;
	
	EnterCriticalSection(&m_cs);

	list<ExtListItem *>::iterator itr;
	for(itr = m_list.begin(); itr != m_list.end(); itr++)
	{
		if(IsEqualCLSID((*itr)->m_clsid, rclsid))
		{
			bFound = TRUE;
			break;
		}
	}

	LeaveCriticalSection(&m_cs);

	return bFound;
}
/// This function is to find the clsid according to progid
/// if find it, the return value will be true and pclsid is the clsid
/// otherwise the return value is false and pclsid is NULL
/// author: Youzhi Bao
/// See Chengyu Song's code as reference
BOOLEAN CExtList::IsInExtList(LPCOLESTR progid, LPCLSID pclsid = NULL)
{
	OLECHAR debugstr[2000];
#ifdef _DEBUG
	swprintf_s(debugstr, 200, L"[CExtList::IsInExtList], progid %s", progid);
	OutputDebugString(debugstr);
#endif
	BOOLEAN bFound = FALSE;
	//pclsid = NULL;

	BSTR m_progid = ::SysAllocString(progid);
	if(!m_progid)
		return FALSE;
#ifdef _DEBUG
	swprintf_s(debugstr, 200, L"[CExtList::IsInExtList] Starting find progid %s", progid);
	OutputDebugString(debugstr);
#endif
	EnterCriticalSection(&m_cs);

	list<ExtListItem *>::iterator itr;
	for(itr = m_list.begin(); itr != m_list.end(); itr++)
	{
		//found the progid in the ExtList
		if(BSTR_COMPARE((*itr) -> m_progid, m_progid))
		{
			OutputDebugString(L"[CEmulist::IsInExtList] Find the name");

			swprintf_s(debugstr, 200, L"[CExtList::IsInExtList] Find the clsid0 %08x, pclsid %08x", (*itr) ->m_clsid, pclsid);
			OutputDebugString(debugstr);
			
			//StringFromCLSID((*itr) ->m_clsid, *pclsid);
			*pclsid = (*itr) -> m_clsid;
			
			bFound = TRUE;
			break;
		}
		else{
			swprintf_s(debugstr, 200, L"[CExtList::IsInExtList] Find the clsid %08x, pclsid %08x", (*itr) ->m_clsid, pclsid);
			OutputDebugString(debugstr);
		}
	}
#ifdef _DEBUG
	//memset(debugstr, 0, sizeof(debugstr));
	swprintf_s(debugstr, 200, L"[CExtList::IsInExtList] Before Finished: pclsid %08x", pclsid);
	OutputDebugString(debugstr);
	swprintf_s(debugstr, 200, L"[CExtList::IsInExtList] Finished finding progid %s, pclsid %08x", progid, pclsid);
	OutputDebugString(debugstr);
#endif
	LeaveCriticalSection(&m_cs);
	SysFreeString(m_progid);

	return bFound;
}
CExtList::~CExtList(void)
{
	EnterCriticalSection(&m_cs);
	
	list<ExtListItem *>::iterator itr;
	for(itr = m_list.begin(); itr != m_list.end(); itr++)
		delete *itr;

	m_list.clear();

	LeaveCriticalSection(&m_cs);
}

/// This function is to find the clsid according to progid
/// if find it, the return value will be true and pclsid is the clsid
/// otherwise the return value is false and pclsid is NULL
/// author: Youzhi Bao
/// See Chengyu Song's code as reference
BOOLEAN CExtList::GetHookName(REFCLSID pclsid, BSTR &hookname)
{
	OLECHAR debugstr[200];
#ifdef _DEBUG
	swprintf_s(debugstr, 200, L"[CExtList::GetHookName], clsid %08x", pclsid);
	OutputDebugString(debugstr);
#endif
	BOOLEAN bFound = FALSE;
	//pclsid = NULL;

	EnterCriticalSection(&m_cs);

	list<ExtListItem *>::iterator itr;
	OutputDebugString(L"[CEmulist::GetHookName]1111111111111111111111");
	for(itr = m_list.begin(); itr != m_list.end(); itr++)
	{
		OutputDebugString(L"[CEmulist::GetHookName]22222222222");
		//found the progid in the ExtList
		if(IsEqualCLSID((*itr) -> m_clsid, pclsid))
		{
#ifdef _DEBUG
			OutputDebugString(L"[CEmulist::GetHookName] Find the clsid");
			swprintf_s(debugstr, 200, L"[CExtList::GetHookName] Find the clsid %08x, pclsid %08x", (*itr) ->m_clsid, pclsid);
			OutputDebugString(debugstr);
#endif		
			//swprintf_s(hookname, 100, L"%s", (*itr) ->m_hookname);
			hookname = (*itr) ->m_hookname;
			OutputDebugString((*itr) ->m_hookname);
			//StringFromCLSID((*itr) ->m_clsid, *pclsid);
			//*pclsid = (*itr) -> m_clsid;
			
			bFound = TRUE;
			break;
		}
		else
			OutputDebugString(L"[CExtList::GetHookName] Not find yet, continue");
	}
#ifdef _DEBUG
	//memset(debugstr, 0, sizeof(debugstr));
	swprintf_s(debugstr, 200, L"[CExtList::GetHookName] Before Finished: pclsid %08x", pclsid);
	OutputDebugString(debugstr);
	OutputDebugString(hookname);
#endif
	LeaveCriticalSection(&m_cs);

	return bFound;
}