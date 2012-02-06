#include "stdafx.h"
#include <fstream>
#include <string>
#include "EmuList.h"

using std::wifstream;
using std::wstring;
using namespace COMSniffer;
CEmuList::CEmuList(void)
{
	InitializeCriticalSection(&m_cs);
}

CEmuList::CEmuList(WCHAR *emulist)
{
	InitializeCriticalSection(&m_cs);

	wifstream wl(emulist);
	if(!wl)
	{
#ifdef _DEBUG
		OutputDebugString(L"[CEmuList::CEmuList]failed to open emulist:");
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
		
		OutputDebugString(L"[CEmuList::CEmulist]Add to emullist");
		OutputDebugString((clsid + L" " + progid + L" " + hookname).c_str());
#ifdef _DEBUG_VERBOSE
		OutputDebugString(L"[[EmuList]Add to emullist");
		OutputDebugString((clsid + L" " + progid).c_str());
#endif

		this->AddToEmuList(hookname.c_str(), (WCHAR *)clsid.c_str(), progid.c_str());

	}

}

BOOLEAN CEmuList::AddToEmuList(LPCOLESTR hookname, LPOLESTR clsid_str, LPCOLESTR progid)
{
	CLSID clsid;

	if(FAILED(CLSIDFromString(clsid_str, &clsid)))
		return FALSE;
	return this->AddToEmuList(hookname, clsid, progid);
}
/// This function is to add a new item into the list
/// The list is list<REFCLSID rclsid, BSTR progid>
BOOLEAN CEmuList::AddToEmuList(LPCOLESTR hookname, REFCLSID rclsid, LPCOLESTR progid)
{
	BSTR m_progid, m_hookname;
	// 0. convert the type of progid
	m_progid = ::SysAllocString(progid);
	if(!m_progid)
		return FALSE;
	m_hookname = ::SysAllocString(hookname);
	if(!m_hookname)
		return FALSE;
	// 1. new an EmuListItem
	EmuListItem *item = new EmuListItem(m_hookname, rclsid, m_progid);
	if(!item)
		return FALSE;

	// 2. push the item into the list
	EnterCriticalSection(&m_cs);
	m_list.push_back(item);
	LeaveCriticalSection(&m_cs);
	return TRUE;
}
BOOLEAN CEmuList::IsInEmuList(REFCLSID rclsid)
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

	list<EmuListItem *>::iterator itr;
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
BOOLEAN CEmuList::IsInEmuList(LPCOLESTR progid, LPCLSID pclsid = NULL)
{
	OLECHAR debugstr[2000];
#ifdef _DEBUG
	swprintf_s(debugstr, 200, L"[CEmuList::IsInEmuList], progid %s", progid);
	OutputDebugString(debugstr);
#endif
	BOOLEAN bFound = FALSE;
	//pclsid = NULL;

	BSTR m_progid = ::SysAllocString(progid);
	if(!m_progid)
		return FALSE;
#ifdef _DEBUG
	swprintf_s(debugstr, 200, L"[CEmuList::IsInEmuList] Starting find progid %s", progid);
	OutputDebugString(debugstr);
#endif
	EnterCriticalSection(&m_cs);

	list<EmuListItem *>::iterator itr;
	for(itr = m_list.begin(); itr != m_list.end(); itr++)
	{
		//found the progid in the EmuList
		if(BSTR_COMPARE((*itr) -> m_progid, m_progid))
		{
			OutputDebugString(L"[CEmulist::IsInEmuList] Find the name");

			swprintf_s(debugstr, 200, L"[CEmuList::IsInEmuList] Find the clsid0 %08x, pclsid %08x", (*itr) ->m_clsid, pclsid);
			OutputDebugString(debugstr);
			
			//StringFromCLSID((*itr) ->m_clsid, *pclsid);
			*pclsid = (*itr) -> m_clsid;
			
			bFound = TRUE;
			break;
		}
		else{
			swprintf_s(debugstr, 200, L"[CEmuList::IsInEmuList] Go on finding the clsid %08x, pclsid %08x", (*itr) ->m_clsid, pclsid);
			OutputDebugString(debugstr);
		}
	}
#ifdef _DEBUG
	//memset(debugstr, 0, sizeof(debugstr));
	swprintf_s(debugstr, 200, L"[CEmuList::IsInEmuList] Before Finished: pclsid %08x", pclsid);
	OutputDebugString(debugstr);
	swprintf_s(debugstr, 200, L"[CEmuList::IsInEmuList] Finished finding progid %s, pclsid %08x", progid, pclsid);
	OutputDebugString(debugstr);
#endif
	LeaveCriticalSection(&m_cs);
	SysFreeString(m_progid);

	return bFound;
}
CEmuList::~CEmuList(void)
{
	EnterCriticalSection(&m_cs);
	
	list<EmuListItem *>::iterator itr;
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
BOOLEAN CEmuList::GetHookName(REFCLSID pclsid, BSTR &hookname)
{
	OLECHAR debugstr[MAX_PATH];
#ifdef _DEBUG
	swprintf_s(debugstr, 200, L"[CEmuList::GetHookName], clsid %08x", pclsid);
	OutputDebugString(debugstr);
#endif
	BOOLEAN bFound = FALSE;
	//pclsid = NULL;

	EnterCriticalSection(&m_cs);

	list<EmuListItem *>::iterator itr;
	OutputDebugString(L"[CEmulist::GetHookName]1111111111111111111111");
	for(itr = m_list.begin(); itr != m_list.end(); itr++)
	{
		OutputDebugString(L"[CEmulist::GetHookName]22222222222");
		//found the progid in the EmuList
		if(IsEqualCLSID((*itr) -> m_clsid, pclsid))
		{
#ifdef _DEBUG
			OutputDebugString(L"[CEmulist::GetHookName] Find the clsid");
			swprintf_s(debugstr, 200, L"[CEmuList::GetHookName] Find the clsid %08x, pclsid %08x", (*itr) ->m_clsid, pclsid);
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
			OutputDebugString(L"[CEmuList::GetHookName] Not find yet, continue");
	}
#ifdef _DEBUG
	//memset(debugstr, 0, sizeof(debugstr));
	swprintf_s(debugstr, 200, L"[CEmuList::GetHookName] Before Finished: pclsid %08x", pclsid);
	OutputDebugString(debugstr);
	OutputDebugString(hookname);
#endif
	LeaveCriticalSection(&m_cs);

	return bFound;
}