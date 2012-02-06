#include "stdafx.h"
#include "HookInfo.h"
#include "HookedMethod.h"

using namespace COMSniffer;

CBaseHookInfo::CBaseHookInfo(REFCLSID rclsid, PVOID vtbl)
{
	this->m_clsid = rclsid;
	this->m_vtbl = vtbl;

	this->m_Ref = 0;
	InitializeCriticalSection(&m_cs);
}

CLSID CBaseHookInfo::GetCLSID(const PVOID object)
{
	CLSID result = CLSID_NULL;

	EnterCriticalSection(&m_cs);

	map<PVOID, CLSID>::iterator itr = m_objects.find(object);
	if(itr != m_objects.end())
		result = itr->second;
	else
		result = this->m_clsid;

	LeaveCriticalSection(&m_cs);

	return result;
}

LONG CBaseHookInfo::AddRef(const PVOID object, REFCLSID clsid, BOOLEAN locked = TRUE)
{
#ifdef _DEBUG
	OLECHAR debugstr[MAX_PATH];
	LPOLESTR sclsid;

	StringFromCLSID(clsid, &sclsid);
	swprintf_s(debugstr, L"[CBaseHookInfo::AddRef] %s, object %08x", sclsid, object);
	OutputDebugString(debugstr);
	CoTaskMemFree(sclsid);
#endif

	LONG ref;

	if(locked) 
		EnterCriticalSection(&m_cs);

	m_objects[object] = clsid;

	ref = ++m_Ref;

	if(locked)
		LeaveCriticalSection(&m_cs);

	return ref;
}

LONG CBaseHookInfo::Release(const PVOID object, BOOLEAN locked = TRUE)
{
	LONG ref;

	if(locked) 
		EnterCriticalSection(&m_cs);

	m_objects.erase(object);

	ref = --m_Ref;

	if(locked) 
		LeaveCriticalSection(&m_cs);

	return ref;
}

CIDispatchHookInfo::CIDispatchHookInfo(REFCLSID rclsid, IDispatchVtbl *vtbl)
: CBaseHookInfo(rclsid, vtbl)
{
#ifdef _DEBUG
	OLECHAR debugstr[MAX_PATH];
	LPOLESTR clsid;

	StringFromCLSID(rclsid, &clsid);
	swprintf_s(debugstr, L"[CIDispatchHookInfo::CIDispatchHookInfo] Hook IDispatch for clsid: %s, vtable %08x", clsid, vtbl);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif

	InitializeCriticalSection(&this->MethodCS);

	DWORD dwOldProtectionFlags, dwOldProtectionFlags2;

	// save vtable functions
	this->QueryInterface = vtbl->QueryInterface;
	this->Release = vtbl->Release;

	swprintf_s(debugstr, MAX_PATH, L"[CIDispatchHookInfo]!!!!!!vftable is %08x, is that useful??", vtbl);
	OutputDebugString(debugstr);

	swprintf_s(debugstr, MAX_PATH, L"[CIDispatchHookInfo]!!!!!!vftable is %08x, is that useful??", vtbl->Invoke);
	OutputDebugString(debugstr);


#ifdef _DEBUG
	if(this->Release == MyRelease)
	{
		swprintf_s(debugstr, TEXT("vftable %08x was not properly unhooked!"), vtbl);
		OutputDebugString(debugstr);
	}
#endif

	this->GetIDsOfNames = vtbl->GetIDsOfNames;
#ifdef _DEBUG
	if(this->GetIDsOfNames == MyGetIDsOfNames)
	{
		swprintf_s(debugstr, TEXT("vftable %08x was not properly unhooked!"), vtbl);
		OutputDebugString(debugstr);
	}
#endif

	this->Invoke = vtbl->Invoke;
#ifdef _DEBUG
	if(this->Invoke == MyInvoke)
	{
		swprintf_s(debugstr, TEXT("vftable %08x was not properly unhooked!"), vtbl);
		OutputDebugString(debugstr);
	}
#endif

	// hook vtable
	if(!VirtualProtect(vtbl, sizeof(IDispatchVtbl), PAGE_EXECUTE_READWRITE, &dwOldProtectionFlags))
	{
#ifdef _DEBUG
		OutputDebugString(L"[CIDispatchHookInfo] unable to change virtual protect flag for hooking.");
#endif
		return;
	}

	InterlockedExchangePointer(&vtbl->QueryInterface, MyQueryInterface);
	InterlockedExchangePointer(&vtbl->Release, MyRelease);

	InterlockedExchangePointer(&vtbl->GetIDsOfNames, MyGetIDsOfNames);
	InterlockedExchangePointer(&vtbl->Invoke, MyInvoke);

	VirtualProtect(vtbl, sizeof(IDispatchVtbl), dwOldProtectionFlags, &dwOldProtectionFlags2);
}

CIDispatchHookInfo::~CIDispatchHookInfo()
{
#ifdef _DEBUG
	OLECHAR debugstr[MAX_PATH];
	LPOLESTR clsid;

	StringFromCLSID(this->m_clsid, &clsid);
	swprintf_s(debugstr, L"Unhook IDispatch for clsid: %s, vtable %08x", clsid, this->m_vtbl);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif

	// cleanup saved method<->id pairs
	EnterCriticalSection(&this->MethodCS);

	map<PVOID, map<DISPID, BSTR> >::iterator itr = this->Methods.begin();
	for(; itr != Methods.end(); itr++)
	{
		map<DISPID, BSTR>::iterator itr2 = itr->second.begin();
		for(; itr2 != itr->second.end(); itr2++)
			SysFreeString(itr2->second);
	}

	LeaveCriticalSection(&this->MethodCS);

	IDispatchVtbl *vtbl = (IDispatchVtbl *)this->m_vtbl;

	if(vtbl->Invoke == MyInvoke)
	{
		// unhook vtable
		DWORD dwOldProtectionFlags, dwOldProtectionFlags2;

		if(!VirtualProtect(vtbl, sizeof(IDispatchVtbl), PAGE_EXECUTE_READWRITE, &dwOldProtectionFlags))
			return;

		InterlockedExchangePointer(&vtbl->QueryInterface, this->QueryInterface);
		InterlockedExchangePointer(&vtbl->Release, this->Release);
#ifdef _DEBUG
		if(vtbl->Release == MyRelease)
		{
			swprintf_s(debugstr, 200, L"~CIDispatchHookInfo(): exchange pointer failed for Release, %08x, %08x, %08x",
				vtbl->Release, this->Release, MyRelease);
			OutputDebugString(debugstr);
		}
#endif

		InterlockedExchangePointer(&vtbl->GetIDsOfNames, this->GetIDsOfNames);
#ifdef _DEBUG
		if(vtbl->GetIDsOfNames == MyGetIDsOfNames)
		{
			swprintf_s(debugstr, 200, L"~CIDispatchHookInfo(): exchange pointer failed for GetIDsOfNames, %08x, %08x, %08x",
				vtbl->GetIDsOfNames, this->GetIDsOfNames, MyGetIDsOfNames);
			OutputDebugString(debugstr);
		}
#endif

		InterlockedExchangePointer(&vtbl->Invoke, this->Invoke);
#ifdef _DEBUG
		if(vtbl->Invoke == MyInvoke)
		{
			swprintf_s(debugstr, 200, L"~CIDispatchHookInfo(): exchange pointer failed for Invoke, %08x, %08x, %08x",
				vtbl->Invoke, this->Invoke, MyInvoke);
			OutputDebugString(debugstr);
		}
#endif

		VirtualProtect(vtbl, sizeof(IDispatchVtbl), dwOldProtectionFlags, &dwOldProtectionFlags2);
	}
}

BOOLEAN CIDispatchHookInfo::AddDispID(const PVOID object, DISPID dispID, OLECHAR *szName)
{
	BOOLEAN result = TRUE;
	
	EnterCriticalSection(&this->MethodCS);

	if((this->Methods[object][dispID] = SysAllocString(szName)) == NULL)
	{
#ifdef _DEBUG
		OutputDebugString(L"CIDispatchHookInfo::AddDispID: failed to convert name to BSTR");
#endif
		this->Methods[object].erase(dispID);

		result = FALSE;
	}

	LeaveCriticalSection(&this->MethodCS);

	return result;
}

BSTR CIDispatchHookInfo::FindDispID(const PVOID object, DISPID dispID)
{
	BSTR result = NULL;

	EnterCriticalSection(&this->MethodCS);

	map<DISPID, BSTR>::iterator itr = this->Methods[object].find(dispID);

	if(itr == this->Methods[object].end())
		result = NULL;
	else
		result = itr->second;

	LeaveCriticalSection(&this->MethodCS);

	return result;
}

CIClassFactoryHookInfo::CIClassFactoryHookInfo(REFCLSID rclsid, IClassFactoryVtbl *vtbl)
: CBaseHookInfo(rclsid, vtbl)
{
#ifdef _DEBUG
	OLECHAR debugstr[MAX_PATH];
	LPOLESTR clsid;

	StringFromCLSID(rclsid, &clsid);
	swprintf_s(debugstr, 200, L"[CIClassFactoryHookInfo] Hook IClassFactory for clsid: %s, vtable %08x, &vtable->Release %08x", clsid, vtbl, &vtbl->Release);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif

	DWORD dwOldProtectionFlags, dwOldProtectionFlags2;

	// hook & save vtable functions
	this->QueryInterface = vtbl->QueryInterface;
	this->Release = vtbl->Release;
#ifdef _DEBUG
	if(this->Release == MyFRelease){
		OutputDebugString(TEXT("vftable %08x was not properly unhooked!"));
	}
#endif

	this->CreateInstance = vtbl->CreateInstance;
#ifdef _DEBUG
	if(this->CreateInstance == MyCreateInstance)
		OutputDebugString(TEXT("vftable %08x was not properly unhooked!"));
#endif

	// hook vtable
	if(!VirtualProtect(vtbl, sizeof(IClassFactoryVtbl), PAGE_EXECUTE_READWRITE, &dwOldProtectionFlags))
	{
#ifdef _DEBUG
		OutputDebugString(L"[CIClassFactoryHookInfo] unable to change virtual protect flag for hooking.");
#endif
		return;
	}

	InterlockedExchangePointer(&(vtbl->QueryInterface), MyFQueryInterface);
	InterlockedExchangePointer(&vtbl->Release, MyFRelease);
	InterlockedExchangePointer(&vtbl->CreateInstance, MyCreateInstance);

	VirtualProtect(vtbl, sizeof(IClassFactoryVtbl), dwOldProtectionFlags, &dwOldProtectionFlags2);
}

CIClassFactoryHookInfo::~CIClassFactoryHookInfo()
{
#ifdef _DEBUG
	OLECHAR debugstr[MAX_PATH];
	LPOLESTR clsid;

	StringFromCLSID(this->m_clsid, &clsid);
	swprintf_s(debugstr, 200, L"[CIClassFactoryHookInfo] Unhook IClassFactory for clsid: %s, vtable %08x", clsid, this->m_vtbl);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif

	IClassFactoryVtbl *vtbl = (IClassFactoryVtbl *)this->m_vtbl;
	OutputDebugString(L"111111111111");
	if(vtbl->CreateInstance == MyCreateInstance)
	{
		// unhook vtable
		OutputDebugString(L"22222222222222222");
		DWORD dwOldProtectionFlags, dwOldProtectionFlags2;

		if(!VirtualProtect(vtbl, sizeof(IClassFactoryVtbl), PAGE_EXECUTE_READWRITE, &dwOldProtectionFlags))
			return;
		
		InterlockedExchangePointer(&vtbl->QueryInterface, this->QueryInterface);

		InterlockedExchangePointer(&vtbl->Release, this->Release);
#ifdef _DEBUG
		if(vtbl->Release == MyFRelease)
		{
			swprintf_s(debugstr, 200, L"~CIClassFactoryHookInfo(): exchange pointer failed for Release, %08x, %08x, %08x",
				vtbl->Release, this->Release, MyFRelease);
			OutputDebugString(debugstr);
		}
#endif
		
		InterlockedExchangePointer(&vtbl->CreateInstance, this->CreateInstance);
#ifdef _DEBUG
		
		if(vtbl->CreateInstance == MyCreateInstance)
		{
			swprintf_s(debugstr, 200, L"~CIClassFactoryHookInfo(): exchange pointer failed for CreateInstance, %08x, %08x, %08x",
				vtbl->CreateInstance, this->CreateInstance, MyCreateInstance);
			OutputDebugString(debugstr);
		}
#endif
		
		VirtualProtect(vtbl, sizeof(IClassFactoryVtbl), dwOldProtectionFlags, &dwOldProtectionFlags2);
	}
	else OutputDebugString(L"333333333333333333");
}

CIDispatchExHookInfo::CIDispatchExHookInfo(REFCLSID rclsid, IDispatchExVtbl *vtbl)
: CBaseHookInfo(rclsid, vtbl)
{
#ifdef _DEBUG
	OLECHAR debugstr[MAX_PATH];
	LPOLESTR clsid;
	StringFromCLSID(rclsid, &clsid);
	swprintf_s(debugstr, L"Tiffany: Hook IDispatchEx for clsid: %s, vtable %08x", clsid, vtbl);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif

	InitializeCriticalSection(&this->MethodCS);

	DWORD dwOldProtectionFlags, dwOldProtectionFlags2;

	// save vtable functions
	this->QueryInterface = vtbl->QueryInterface;
	this->Release = vtbl->Release;
	this->GetDispID = vtbl->GetDispID;
	this->InvokeEx = vtbl->InvokeEx;
/*#ifdef _DEBUG
	if(this->Release == MyRelease)
	{
		swprintf_s(debugstr, TEXT("vftable %08x was not properly unhooked!"), vtbl);
		OutputDebugString(debugstr);
	}
#endif
*/
	//this->GetIDsOfNames = vtbl->GetIDsOfNames;
/*
#ifdef _DEBUG
	if(this->GetIDsOfNames == MyGetIDsOfNames)
	{
		swprintf_s(debugstr, TEXT("vftable %08x was not properly unhooked!"), vtbl);
		OutputDebugString(debugstr);
	}
#endif
*/
	//this->Invoke = vtbl->Invoke;
/*
#ifdef _DEBUG
	if(this->Invoke == MyInvoke)
	{
		swprintf_s(debugstr, TEXT("vftable %08x was not properly unhooked!"), vtbl);
		OutputDebugString(debugstr);
	}
#endif
*/
	// hook vtable
	if(!VirtualProtect(vtbl, sizeof(IDispatchExVtbl), PAGE_EXECUTE_READWRITE, &dwOldProtectionFlags))
	{
#ifdef _DEBUG
		OutputDebugString(L"CIDispatchHookInfo: unable to change virtual protect flag for hooking.");
#endif
		return;
	}

	//InterlockedExchangePointer(&vtbl->QueryInterface, MyQueryInterface);
	//InterlockedExchangePointer(&vtbl->Release, MyRelease);

	InterlockedExchangePointer(&vtbl->GetDispID, MyGetDispID);
	InterlockedExchangePointer(&vtbl->InvokeEx, MyInvokeEx);

	VirtualProtect(vtbl, sizeof(IDispatchExVtbl), dwOldProtectionFlags, &dwOldProtectionFlags2);
}

CIDispatchExHookInfo::~CIDispatchExHookInfo()
{
#ifdef _DEBUG
	OLECHAR debugstr[MAX_PATH];
	LPOLESTR clsid;
#endif
#ifdef _DEBUG
	StringFromCLSID(this->m_clsid, &clsid);
	swprintf_s(debugstr, L"Unhook IDispatchEx for clsid: %s, vtable %08x", clsid, this->m_vtbl);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif

	// cleanup saved method<->id pairs
	EnterCriticalSection(&this->MethodCS);

#ifdef _DEBUG
	OutputDebugString(L"iterator begin");
#endif
	map<PVOID, map<DISPID, BSTR> >::iterator itr = this->Methods.begin();

	for(; itr != Methods.end(); itr++)
	{
		map<DISPID, BSTR>::iterator itr2 = itr->second.begin();
		for(; itr2 != itr->second.end(); itr2++){
			SysFreeString(itr2->second);
		}
	}

	LeaveCriticalSection(&this->MethodCS);

#ifdef _DEBUG
	OutputDebugString(L"iterator end");
#endif
	IDispatchExVtbl *vtbl = (IDispatchExVtbl *)this->m_vtbl;

	if(vtbl->GetDispID == MyGetDispID)
	{
		// unhook vtable
		DWORD dwOldProtectionFlags, dwOldProtectionFlags2;

		if(!VirtualProtect(vtbl, sizeof(IDispatchExVtbl), PAGE_EXECUTE_READWRITE, &dwOldProtectionFlags))
			return;

/*
		InterlockedExchangePointer(&vtbl->QueryInterface, this->QueryInterface);
		InterlockedExchangePointer(&vtbl->Release, this->Release);

#ifdef _DEBUG
		if(vtbl->Release == MyRelease)
		{
			swprintf_s(debugstr, 200, L"~CIDispatchHookInfo(): exchange pointer failed for Release, %08x, %08x, %08x",
				vtbl->Release, this->Release, MyRelease);
			OutputDebugString(debugstr);
		}
#endif
*/
		InterlockedExchangePointer(&vtbl->GetDispID, this->GetDispID);
/*
#ifdef _DEBUG
		if(vtbl->GetIDsOfNames == MyGetIDsOfNames)
		{
			swprintf_s(debugstr, 200, L"~CIDispatchHookInfo(): exchange pointer failed for GetIDsOfNames, %08x, %08x, %08x",
				vtbl->GetIDsOfNames, this->GetIDsOfNames, MyGetIDsOfNames);
			OutputDebugString(debugstr);
		}
#endif
*/
		InterlockedExchangePointer(&vtbl->InvokeEx, this->InvokeEx);
/*
#ifdef _DEBUG
		if(vtbl->Invoke == MyInvoke)
		{
			swprintf_s(debugstr, 200, L"~CIDispatchHookInfo(): exchange pointer failed for Invoke, %08x, %08x, %08x",
				vtbl->Invoke, this->Invoke, MyInvoke);
			OutputDebugString(debugstr);
		}
#endif
*/
		VirtualProtect(vtbl, sizeof(IDispatchExVtbl), dwOldProtectionFlags, &dwOldProtectionFlags2);
	}
}


BOOLEAN CIDispatchExHookInfo::AddDispID(const PVOID object, DISPID dispID, BSTR szName)
{
	BOOLEAN result = TRUE;
	
	EnterCriticalSection(&this->MethodCS);

	if((this->Methods[object][dispID] = szName) == NULL)
	{
#ifdef _DEBUG
		OutputDebugString(L"CIDispatchExHookInfo::AddDispID: failed to convert name to BSTR");
#endif
		this->Methods[object].erase(dispID);

		result = FALSE;
	}
#ifdef _DEBUG
	OutputDebugString(L"CIDispatchExHookInfo::AddDispID: success");
#endif
	LeaveCriticalSection(&this->MethodCS);

	return result;
}


BSTR CIDispatchExHookInfo::FindDispID(const PVOID object, DISPID dispID)
{
	BSTR result = NULL;

	EnterCriticalSection(&this->MethodCS);

	map<DISPID, BSTR>::iterator itr = this->Methods[object].find(dispID);

	if(itr == this->Methods[object].end())
		result = NULL;
	else
		result = itr->second;

	LeaveCriticalSection(&this->MethodCS);

	return result;
}

