#include "stdafx.h"
#include "HookManager.h"
#include "HookInfo.h"
#include "HookedMethod.h"

using std::pair;
using namespace COMSniffer;

//extern CObjectManager g_ObjManager;

CHookManager::CHookManager()
{
	InitializeCriticalSection(&m_cs);
}

CHookManager::~CHookManager()
{
	EnterCriticalSection(&m_cs);

	map<PVOID, CBaseHookInfo *>::iterator itr = m_hinfo.begin();
	for(; itr != m_hinfo.end(); itr++)
		delete itr->second;

	LeaveCriticalSection(&m_cs);
}

// Name: CHookManager::Find
// Argument: object's interface address
// Function: get the corresponding HookInfo
// 
PVOID CHookManager::Find(const PVOID object)
{
	// 1. get the interface's vtable
	//  since the binary structure (C definition) of IUnknown, IDispatch, IClassFactory or else is the same
	//  here we treat the interface as IUnknown to get its vtable address
	PVOID vtbl = ((IUnknown *)object)->lpVtbl;

#ifdef _DEBUG
	OLECHAR debugstr[MAX_PATH];
	
	swprintf_s(debugstr, 200, L"CHookManager::Find: object %08x, vtable: %08x", object, vtbl);
	OutputDebugString(debugstr);
#endif
	
	// enter critical section to avoid confliction
	EnterCriticalSection(&m_cs);

	// 2. try to find the corresponding HookInfo
	map<PVOID, CBaseHookInfo *>::iterator itr = m_hinfo.find(vtbl);

	LeaveCriticalSection(&m_cs);

	// 3. return the result, NULL if not found
	if(itr != m_hinfo.end())
	{
#ifdef _DEBUG
		OutputDebugString(L"HookInfo found");
#endif

		return itr->second;
	}
	else
	{
#ifdef _DEBUG
		swprintf_s(debugstr, 200, L"HookInfo not found in %08x for object %08x, vtable: %08x", this, object, vtbl);
		OutputDebugString(debugstr);
#endif
		return NULL;
	}
}

// Name: CHookManager::AddRef
// Arguements: 1. object's IDispatch interface; 2. object's CLSID
// Function: hook the object's IDispatch interface
//
BOOLEAN CHookManager::AddRef(IDispatch *object, REFCLSID clsid)
{
	BOOLEAN result = TRUE;

	// 1. get IDispatch interface's vtable
	IDispatchVtbl *vtbl = object->lpVtbl;

#ifdef _DEBUG
	OLECHAR debugstr[MAX_PATH];
	
	swprintf_s(debugstr, 200, L"CHookManager::AddRef(IDispatch): object %08x, vtable: %08x", object, vtbl);
	OutputDebugString(debugstr);
#endif

	// enter critical section to avoid conflict
	EnterCriticalSection(&m_cs);
	
	// 2. check if the vtable has already been hooked
	// 2.1 check if the vtable's HookInfo exists
	CBaseHookInfo *pInfo = NULL;
	map<PVOID, CBaseHookInfo *>::iterator itr = m_hinfo.find(vtbl);

	// 2.2 if yes, check it has really been hooked
	//	this is necessary since I use a lazy deletion strategy
	if(itr != m_hinfo.end())
	{
#ifdef _DEBUG
		swprintf_s(debugstr, 200, L"CHookManager::AddRef: HookInfo found for object %08x, vtable: %08x", object, vtbl);
		OutputDebugString(debugstr);
#endif
		pInfo = itr->second;

		// check if the vtable's Invoke function points to MyInvoke
		if(vtbl->Invoke != MyInvoke)
		{
#ifdef _DEBUG
			OutputDebugString(L"CHookManager::AddRef: HookInfo expired");
#endif
			// if not, this is a new object with a new vtable
			// delete the HookInfo
			delete pInfo;
			pInfo = NULL;
		}
	}

	// 2.3 if vtalbe has not been hooked 
	if(!pInfo)
	{
		// ceate the corresponding HookInfo
		pInfo = new CIDispatchHookInfo(clsid, vtbl);
		if(!pInfo)
		{
#ifdef _DEBUG
			OutputDebugString(L"CHookManager::AddRef: failed to allocate hook info");
#endif

			result = FALSE;
			goto ERROR_ABORT;
		}

		// save the mapping
		m_hinfo[vtbl] = pInfo;
	}

	// 3. call the HookInfo's AddRef method
	pInfo->AddRef(object, clsid, FALSE);

ERROR_ABORT:
	LeaveCriticalSection(&m_cs);

	return result;
}
// Name: CHookManager::AddRef
// Arguements: 1. object's IDispatch interface; 2. object's CLSID
// Function: hook the object's IDispatch interface
//
BOOLEAN CHookManager::AddRef(IDispatchEx *object, REFCLSID clsid)
{
	BOOLEAN result = TRUE;

	// 1. get IDispatch interface's vtable
	IDispatchExVtbl *vtbl = object->lpVtbl;

#ifdef _DEBUG
	OLECHAR debugstr[MAX_PATH];
	
	swprintf_s(debugstr, 200, L"[CHookManager::AddRef(IDispatchEx)] object %08x, vtable: %08x", object, vtbl);
	OutputDebugString(debugstr);
#endif

	// enter critical section to avoid conflict
	EnterCriticalSection(&m_cs);
	
	// 2. check if the vtable has already been hooked
	// 2.1 check if the vtable's HookInfo exists
	CBaseHookInfo *pInfo = NULL;
	map<PVOID, CBaseHookInfo *>::iterator itr = m_hinfo.find(vtbl);

	// 2.2 if yes, check it has really been hooked
	//	this is necessary since I use a lazy deletion strategy
	if(itr != m_hinfo.end())
	{
#ifdef _DEBUG
		swprintf_s(debugstr, 200, L"[CHookManager::AddRef(IDiaptchEx)] HookInfo found for object %08x, vtable: %08x", object, vtbl);
		OutputDebugString(debugstr);
#endif
		pInfo = itr->second;

		// check if the vtable's Invoke function points to MyInvoke
		if(vtbl->GetDispID != MyGetDispID)
		{
#ifdef _DEBUG
			OutputDebugString(L"CHookManager::AddRef: HookInfo expired");
#endif
			// if not, this is a new object with a new vtable
			// delete the HookInfo
			delete pInfo;
			pInfo = NULL;
		}
	}

	// 2.3 if vtalbe has not been hooked 
	if(!pInfo)
	{
		// ceate the corresponding HookInfo
		pInfo = new CIDispatchExHookInfo(clsid, vtbl);
		if(!pInfo)
		{
#ifdef _DEBUG
			OutputDebugString(L"CHookManager::AddRefDispatchEx: failed to allocate hook info");
#endif

			result = FALSE;
			goto ERROR_ABORT;
		}

		// save the mapping
		m_hinfo[vtbl] = pInfo;
	}

	// 3. call the HookInfo's AddRef method
	pInfo->AddRef(object, clsid, FALSE);

ERROR_ABORT:
	LeaveCriticalSection(&m_cs);

	return result;
}

// Name: CHookManager::AddRef
// Arguements: 1. object's IClassFactory interface; 2. object's CLSID
// Function: hook the object's IClassFactory interface
// Comments: see AddRef for IDispatch for more info
//
BOOLEAN CHookManager::AddRef(IClassFactory *object, REFCLSID clsid)
{
	BOOLEAN result = TRUE;
	IClassFactoryVtbl *vtbl = object->lpVtbl;

#ifdef _DEBUG
	LPOLESTR sclsid;
	OLECHAR debugstr[MAX_PATH];
	StringFromCLSID(clsid, &sclsid);
	swprintf_s(debugstr, 200, L"[CHookManager::AddRef(IClassFactory)] class: %s, object: %08x, vtable: %08x", sclsid, object, vtbl);
	OutputDebugString(debugstr);
#endif

	EnterCriticalSection(&m_cs);
	
	CBaseHookInfo *pInfo = NULL;
	//check if vtble has been hooked, which will exists in map
	//PVOID: vtable address
	map<PVOID, CBaseHookInfo *>::iterator itr = m_hinfo.find(vtbl);

	if(itr != m_hinfo.end())
	{
		pInfo = itr->second;
		//不理解为什么会有vtlb->createInstance不是MyCreateInstance的时候，既然已经都hook了
		if(vtbl->CreateInstance != MyCreateInstance)
		{
			//都delete了怎么还可以设值成NULL？
			delete pInfo;
			pInfo = NULL;
		}
	}
	//If no pInfo exists create a new pInfo with clsid and vtbl
	if(pInfo == NULL)
	{
		OutputDebugString(L"[CHookManager::AddRef(IClassFactory)] go to new a IClassFactoryHookInfo...");
		pInfo = new CIClassFactoryHookInfo(clsid, vtbl);
		if(!pInfo)
		{
#ifdef _DEBUG
			OutputDebugString(L"[CHookManager::AddRef(IClassFactory)] failed to allocate hook info");
#endif

			result = FALSE;
			goto ERROR_ABORT;
		}
		//Add new hook into map
		m_hinfo[vtbl] = pInfo;
	}

	pInfo->AddRef(object, clsid, FALSE);
#ifdef _DEBUG
	OutputDebugString(L"[CHookManager::AddRef(IClassFactory)] AddRef Finished");
#endif
ERROR_ABORT:
	LeaveCriticalSection(&m_cs);

	return result;
}

// Name: CHookManager::Release
// Arguements: object's interface
// Function: unhook the interface
//
VOID CHookManager::Release(CBaseHookInfo *HookInfo, const PVOID object, const PVOID vtbl)
{

#ifdef _DEBUG
	OLECHAR debugstr[MAX_PATH];
	
	swprintf_s(debugstr, 200, L"[CHookManager::Release] object %08x, vftable %08x", object, vtbl);
	OutputDebugString(debugstr);
#endif

	// enter critical section to avoid confliction
	EnterCriticalSection(&m_cs);
	
	// 1. call the HooInfo's Release method
	LONG ref = HookInfo->Release(object, FALSE);

	// 2. if the reference decreased to 0, delete the HookInfo
	//  which in turn, unhooks the corresponding interface
	//
	// use lazy deletion
	//
	//if(ref == 0)
	//{
	//	delete HookInfo;
	//	m_hinfo.erase(vtbl);
	//}

	LeaveCriticalSection(&m_cs);
}