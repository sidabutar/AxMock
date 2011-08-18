#include "stdafx.h"
#include <fstream>
#include <string>
#include "AvailableList.h"

using std::wifstream;
using std::wstring;
using namespace COMSniffer;

CAvailableList::CAvailableList()
{
	InitializeCriticalSection(&m_cs);

	//AddToAvailableList(L"{6BE52E1D-E586-474F-A6E2-1A85A9B4D9FB}", L"MPS.StormPlayer.1");
}

CAvailableList::CAvailableList(WCHAR *blacklist)
{
	InitializeCriticalSection(&m_cs);

	wifstream wl(blacklist);
	if(!wl)
	{
#ifdef _DEBUG
		OutputDebugString(L"failed to open blacklist:");
		OutputDebugString(blacklist);
#endif
		return;
	}

	wstring line, clsid, progid;
	while(!wl.eof())
	{
		std::getline(wl, line);
		wstring::size_type index = line.find_first_of(' ');
		clsid = line.substr(0, index);
		progid = line.substr(index+1);

#ifdef _DEBUG_VERBOSE
		OutputDebugString(L"Add to blacklist");
		OutputDebugString((clsid + L" " + progid).c_str());
#endif

		this->AddToAvailableList((WCHAR *)clsid.c_str(), progid.c_str());
	}
}

CAvailableList::~CAvailableList()
{
	EnterCriticalSection(&m_cs);
	
	list<CAvailableList::AvailableListItem *>::iterator itr;
	for(itr = m_list.begin(); itr != m_list.end(); itr++)
		delete *itr;

	m_list.clear();

	LeaveCriticalSection(&m_cs);
}

BOOLEAN CAvailableList::AddToAvailableList(REFCLSID rclsid, LPCOLESTR progid)
{
#ifdef _DEBUG
	LPOLESTR clsid;
	OLECHAR debugstr[1024];

	StringFromCLSID(rclsid, &clsid);
	swprintf_s(debugstr, 200, L"AddToEmulationList: CLSID %s ProgID %s", clsid, progid);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif

	BSTR m_progid = SysAllocString(progid);
	if(!m_progid)
		return FALSE;

	AvailableListItem *item = new AvailableListItem(rclsid, m_progid);
	if(!item)
		return FALSE;
	
	EnterCriticalSection(&m_cs);
	
	/*list<CAvailableList::AvailableListItem *>::iterator itr;
	for(itr = m_list.begin(); itr != m_list.end(); itr++)
	{
		if(IsEqualCLSID((*itr)->m_clsid, rclsid) && 
			(VarBstrCmp((*itr)->m_progid, m_progid, LOCALE_SYSTEM_DEFAULT, 0) == VARCMP_EQ)
		  )
			break;
	}
	if(itr == m_list.end())*/
		m_list.push_back(item);

	LeaveCriticalSection(&m_cs);

	return TRUE;
}

BOOLEAN CAvailableList::AddToAvailableList(LPOLESTR clsid_str, LPCOLESTR progid)
{
	CLSID clsid;

	if(FAILED(CLSIDFromString(clsid_str, &clsid)))
		return FALSE;
		
	return this->AddToAvailableList(clsid, progid);
}

VOID CAvailableList::RemoveFromAvailableList(REFCLSID rclsid)
{
	EnterCriticalSection(&m_cs);
	
	list<AvailableListItem *>::iterator itr;
	for(itr = m_list.begin(); itr != m_list.end(); itr++)
	{
		if(IsEqualCLSID((*itr)->m_clsid, rclsid))
		{
			delete *itr;
			m_list.erase(itr);
		}
	}

	LeaveCriticalSection(&m_cs);
}

VOID CAvailableList::RemoveFromAvailableList(LPCOLESTR progid)
{
	BSTR m_progid = SysAllocString(progid);
	if(!m_progid)
		return;

	EnterCriticalSection(&m_cs);
	
	list<AvailableListItem *>::iterator itr;
	for(itr = m_list.begin(); itr != m_list.end(); itr++)
	{
		if(BSTR_COMPARE((*itr)->m_progid, m_progid))
		{
			delete *itr;
			m_list.erase(itr);
		}
	}

	LeaveCriticalSection(&m_cs);

	SysFreeString(m_progid);
}

BOOLEAN CAvailableList::IsInAvailableList(REFCLSID rclsid)
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

	list<AvailableListItem *>::iterator itr;
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

BOOLEAN CAvailableList::IsInAvailableList(LPCOLESTR progid, LPCLSID pclsid)
{
#ifdef _DEBUG
	OutputDebugString(L"CAvailableList::IsInAvailableList");
	OutputDebugString(progid);
#endif

	BOOLEAN bFound = FALSE;

	BSTR m_progid = SysAllocString(progid);
	if(!m_progid)
		return bFound;

	EnterCriticalSection(&m_cs);

	list<AvailableListItem *>::iterator itr;
	for(itr = m_list.begin(); itr != m_list.end(); itr++)
	{
		if(BSTR_COMPARE((*itr)->m_progid, m_progid))
		{
#ifdef _DEBUG
			OutputDebugString(L"CAvailableList::IsInAvailableList: found");
#endif

			*pclsid = (*itr)->m_clsid;
			bFound = TRUE;
			break;
		}
	}

	LeaveCriticalSection(&m_cs);

	SysFreeString(m_progid);

	return bFound;
}

BOOLEAN CAvailableList::ProgIDFromCLSID(REFCLSID rclsid, LPOLESTR *progid)
{
#ifdef _DEBUG
	LPOLESTR clsid;
	StringFromCLSID(rclsid, &clsid);
	OutputDebugString(L"CAvailableList::ProgIDFromCLSID");
	OutputDebugString(clsid);
	CoTaskMemFree(clsid);
#endif

	BOOLEAN bFound = FALSE;
	
	EnterCriticalSection(&m_cs);

	list<AvailableListItem *>::iterator itr;
	for(itr = m_list.begin(); itr != m_list.end(); itr++)
	{
		if(IsEqualCLSID((*itr)->m_clsid, rclsid))
		{
			UINT progid_len = SysStringLen((*itr)->m_progid);
			SIZE_T progid_size = (progid_len + 1) * sizeof(OLECHAR); //SysStringLen returns char numbers and without tailing null
			*progid = (LPOLESTR)CoTaskMemAlloc(progid_size);
			if(*progid != NULL)
			{
				memcpy(*progid, (*itr)->m_progid, progid_size - 2);
				(*progid)[progid_len] = UNICODE_NULL;
				bFound = TRUE;
			}
			
			break;
		}
	}

	LeaveCriticalSection(&m_cs);

	// if not found, try COM library
	if(!bFound)
	{
		if(SUCCEEDED(ProgIDFromCLSID(rclsid, progid)))
		{
			bFound = TRUE;
		}
	}

	return bFound;
}