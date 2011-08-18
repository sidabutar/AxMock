#include "stdafx.h"
#include <stdio.h>
#include <iostream>
#include <wchar.h>
#include <ole2.h>

#include "HookManager.h"
#include "AvailableList.h"
#include "EmuList.h"
#include "ExtList.h"

#include "COMEmu.h"

#include "madCHook/madCHook.h"

using namespace COMSniffer;
using namespace std;

/// Global known ProgID <-> CLSID list (blacklist)
CAvailableList *g_AList;

/// Global HookInfo manager
CHookManager *g_HookManager;

/// Global Emulating List
CEmuList *g_EmuList;

/// Global Existing List
CExtList *g_ExtList;

IClassFactory *emuppv;
IDispatch *emuIDispatch;
IDispatchEx *emuIDispatchEx;

typedef HRESULT (WINAPI *COCREATEINSTANCEEX)(
	REFCLSID rclsid,
	IUnknown * punkOuter,
	DWORD dwClsCtx,
	COSERVERINFO * pServerInfo,
	DWORD cmq,
	MULTI_QI * pResults
	);

///
/// \brief Function pointer to save the original CoCreateInstanceEx
/// \see MyCoCreateInstanceEx
///
COCREATEINSTANCEEX OriginCoCreateInstanceEx;

///
/// \brief Callback function for CoCreateInstanceEx
///
/// This function has two duties.
/// First, it monitors the creation of COM objects to:
///		1. notify MwDetector with object creation event;
///		2. hook the IDispatch interface of the created ActiveX control object.
/// Second, it create a COMEmu object in case the required component is not installed.
///
/// \param[in] rclsid CLSID of the COM component.
/// \param[in] punkOuter Not touched, see MSDN for more info.
/// \param[in] dwClsCtx Not used, see MSDN for more info.
/// \param[in] pServerInfo Not used, see MSDN for more info.
/// \param[in] cmq Number of structures in pResults.
/// \param[in,out] pResult An array of MULTI_QI structures.
/// \return The creation result
///
extern "C" __declspec(dllexport)
HRESULT WINAPI MyCoCreateInstanceEx(
	REFCLSID rclsid,
	IUnknown * punkOuter,
	DWORD dwClsCtx,
	COSERVERINFO * pServerInfo,
	DWORD cmq,
	MULTI_QI * pResults
	)
{
	HRESULT result, re;
	IDispatch *lpDispatch;
	IDispatchEx *lpDispatchEx;
	DWORD i;
#ifdef _DEBUG
	LPOLESTR clsid;
	OLECHAR debugstr[200];
	StringFromCLSID(rclsid, &clsid);
	swprintf_s(debugstr, 200, L"[CoCreateInstanceEx] ClassID is %s", clsid);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif

	// 1. call the original function
	result = OriginCoCreateInstanceEx(rclsid, punkOuter, dwClsCtx, pServerInfo, cmq, pResults);
	if(FAILED(result)){
#ifdef _DEBUG
		swprintf_s(debugstr, 200, L"[CoCreateInstanceEx] Instance Creation Error. Result: %0x", result);
		OutputDebugString(debugstr);
#endif
		goto ERROR_ABORT;
	}
	// 2. check if the CLSID is in monitor list (blacklist)
	if(!g_AList->IsInAvailableList(rclsid) && !g_EmuList->IsInEmuList(rclsid) && !g_ExtList->IsInExtList(rclsid)){
#ifdef _DEBUG
		OutputDebugString(L"[CoCreateInstanceEx] UnMonitor one, goto error_abort");
#endif
		goto ERROR_ABORT;
	}

	re = pResults[0].pItf->lpVtbl->QueryInterface(pResults[0].pItf, IID_IDispatchEx, &(PVOID&)lpDispatchEx);
	re = pResults[0].pItf->lpVtbl->QueryInterface(pResults[0].pItf, IID_IDispatch, &(PVOID&)lpDispatch);

	
	// 3. looking for IDispath interface
	// This may not be necessary now, as all components in blacklist
	// should has IDispatch interface.
	//
	// Each MULTI_QI structure has three members:
	//   a. the identifier for a requested interface (pIID),
	//   b. the location to return the interface pointer (pItf) and
	//   c. the return value of the call to QueryInterface (hr).
	for(i = 0; i < cmq; i++)
	{
		if(IsEqualIID(*(pResults[i].pIID), IID_IDispatch))
			break;
	}
	// 3.1 if not found, check if the object supports IDispatch
	if(i == cmq)
	{
#ifdef _DEBUG
		OutputDebugString(L"[CoCreateInstanceEx] query for IDispatch");
#endif
		//XXX use the first interface
		//details for http://blogs.msdn.com/b/oldnewthing/archive/2004/02/05/68017.aspx
		re = pResults[0].pItf->lpVtbl->QueryInterface(pResults[0].pItf, IID_IDispatch, &(PVOID&)lpDispatch);

		// if it doesn't support, do not handle such objects now
		if(FAILED(re))
		{
			goto ERROR_ABORT;
		}
	}
	// 3.2 if found, use that interface
	else
	{
		lpDispatch = (IDispatch *)pResults[i].pItf;
		lpDispatch->lpVtbl->AddRef(lpDispatch); // increase the reference as we copied the interface instance
	}

#ifdef _DEBUG
	OutputDebugString(L"[CoCreateInstanceEx] object supports IDispatch");
#endif


	// 4. hook the IDispatch interface
	OutputDebugString(L"[CoCreateInstanceEx] HookManager gonna work!!!!!!");
	g_HookManager->AddRef(lpDispatch, rclsid); //FIXME check result

	// 5. release the queried or copied interface
	lpDispatch->lpVtbl->Release(lpDispatch);

ERROR_ABORT:
	return result;
}

///
/// \brief Function pointer prototype for CoGetClassObject
///
/// Calling convetion: __stdcall
///
/// \see MyCoGetClassObject
///
typedef HRESULT (WINAPI * COGETCLASSOBJECT)(
	REFCLSID rclsid,
	DWORD dwClsContext,
	LPVOID pServerInfo,
	REFIID riid,
	LPVOID * ppv
	);

///
/// \brief Function pointer to save the original CoGetClassObject
/// \see MyCoGetClassObject
///
COGETCLASSOBJECT RealCoGetClassObject;

///
/// \brief Callback function for CoGetClassObject
/// This function will hook the Class Factory of this component
/// Whether the clsid is offered by MyGetPROGIDFromClsid or the webpage, the clsid is valid so can call the origin function.
/// Hence, what we do in MyCoGetClassObject is to log the creation, and hook the class factory.
/// \param[in] rclsid CLSID of the COM component.
/// \param[in] dwClsCtx Not used, see MSDN for more info.
/// \param[in] pServerInfo Not used, see MSDN for more info.
/// \param[in] riid IID of the required interface.
/// \param[out] ppv Pointer to the required interface.
/// \return The creation result
///
extern "C" __declspec(dllexport)
HRESULT WINAPI MyCoGetClassObject(
	REFCLSID rclsid,
	DWORD dwClsContext,
	LPVOID pServerInfo,
	REFIID riid,
	LPVOID * ppv
	)
{
	HRESULT result, re;
	IClassFactory *lpFactory;
	
#ifdef _DEBUG
	LPOLESTR clsid;
	OLECHAR debugstr[200];
#endif

#ifdef _DEBUG
	StringFromCLSID(rclsid, &clsid);
	swprintf_s(debugstr, 200, L"[CoGetClassObject] Class ID %s, Interface ID %08x", clsid, riid);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif
	// 1. call the original function
	result = RealCoGetClassObject(rclsid, dwClsContext, pServerInfo, riid, ppv);
	// 1+. If it is not in the moniter list, let it go
	if(!g_AList->IsInAvailableList(rclsid) && !g_EmuList->IsInEmuList(rclsid) && !g_ExtList->IsInExtList(rclsid)){
		OutputDebugString(L"[CoGetClassObject] real one, goto error_abort");
		return result;
	}
	if(FAILED(result)){
		OutputDebugString(L"[CoGetClassObject] Fake one, creation error");
		return result;
	}
	// 2. check if the interface queried is IClassFactory
	if(IsEqualIID(riid, IID_IClassFactory))
	{
#ifdef _DEBUG
		OutputDebugString(L"[CoGetClassObject] query interface is IClassFactory");
#endif
		// 2.1 if is, copy the interface pointer
		lpFactory = (IClassFactory *)(*ppv);
		lpFactory->lpVtbl->AddRef(lpFactory);
	}
	else
	{
		// 2.2 if not, query for the IClassFactory interface
		// It seems that the query Interface will addref IClassFactory
		re = ((IUnknown *)(*ppv))->lpVtbl->QueryInterface((IUnknown *)(*ppv), IID_IClassFactory, &(PVOID&)lpFactory);
		if(FAILED(re)) //FIXME log the error reason
		{
#ifdef _DEBUG
			OutputDebugString(L"[CoGetClassObject] failed to query IClassFactory");
#endif
			goto ERROR_ABORT;
		}
	}
	
	// 3. hook the IClassFactory interface
#ifdef _DEBUG
	OutputDebugString(L"[CoGetClassObject]Hook the IClassFactory: HookManager -> AddRef");
#endif
	g_HookManager->AddRef((IClassFactory*)(*ppv), rclsid); //FIXME check result

	// 4. release the queried or copied interface
#ifdef _DEBUG
	OutputDebugString(L"[CoGetClassObject] goto HookManager -> Release...");
#endif
	lpFactory->lpVtbl->Release(lpFactory);

ERROR_ABORT:
	return result;
}

///
/// \brief Function pointer prototype for CLSIDFromProgID
///
/// Calling convetion: __stdcall
///
/// \see MyCLSIDFromProgID
///
typedef HRESULT (WINAPI * CLSIDFROMPROGID)(
	LPCOLESTR lpszProgID,
	LPCLSID pclsid
	);

///
/// \brief Function pointer to save the original CLSIDFromProgID
/// \see MyCLSIDFromProgID
///
CLSIDFROMPROGID RealCLSIDFromProgID;

///
/// \brief Callback function for CLSIDFromProgID
///
/// This function first checks if the ProgID is in the known (blacklist) ProgID list,
/// if is, it returns the corresponding CLSID; else it calls the original function
/// to search in Windows Registry.
/// If the calling of original function failes, a FAKE CLSID is created,
/// and then stored in the known ProgID <-> CLSID list.
/// \param[in] lpszProgID The ProgID of which the corresponding CLSID is going to be searched.
/// \param[out] pclsid The corresponding CLSID.
/// \return The search result
///
extern "C" __declspec(dllexport)
HRESULT WINAPI MyCLSIDFromProgID(
	LPCOLESTR lpszProgID,
	LPCLSID pclsid
	)
{
#ifdef _DEBUG
	OutputDebugString(L"[CLSIDFromProgID] MyCLSIDFromProgID");
#endif
	HRESULT re;
	//LPCLSID tpclsid = new CLSID;
	if(g_EmuList -> IsInEmuList(lpszProgID, pclsid)){
#ifdef _DEBUG
		OutputDebugString(L"[CLSIDFromProgID] In the Emulist");
#endif
		//pclsid = tpclsid;
		re = TRUE;
	}
	// temporary disabled
	//else if (g_Extlist -> IsInExtlist(lpszProgID, pclsid))
	//	re = TRUE;
	else
	{
#ifdef _DEBUG
		OutputDebugString(L"[CLSIDFromProgID] Not in the Emulist");
#endif	
		re = RealCLSIDFromProgID(lpszProgID, pclsid);
	}
	return re;
	
	
#if 0 //temporary disabled

		// if this also fails, create a FAKE one
		if(wcsstr(lpszProgID, L"XMLHTTP") != UNICODE_NULL)
			return re;

		// the format is '{now_tick_cout-4A5C-11D3-0F0F-0F0F0F0F0F0F}'
		DWORD nowtime = GetTickCount();
		pclsid->Data1 = nowtime;
		pclsid->Data2 = 0x4A5C;
		pclsid->Data3 = 0x11D3;
		for (int i = 0; i < 8; i++)
			pclsid->Data4[i] = 0x0F;

		// store the ProgID - FAKE CLSID pair
		g_AList->AddToAvailableList(*pclsid, lpszProgID);

		re = S_OK;

#endif
}

///
/// @brief DLL entry point.
///
/// This function:
///   on DLL_PROCESS_ATTACH: initializes the global objects and hooks the COM library;
///   on DLL_PROCESS_DETACH: destroys the global objects and unhooks the COM Library.
///
/// @param[in] hModule Handle for this module.
/// @param[in] ul_reason_for_call Reason for calling.
/// @return Execution result.
///
/// @todo only load when process is MSIE
///
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	//HMODULE hHookDll;

	switch (ul_reason_for_call)
	{
		// Initializing process
	case DLL_PROCESS_ATTACH:

		// 1. create the HookManager
		g_HookManager = new CHookManager;
		if(!g_HookManager)
			return FALSE;

		// get module directory
		WCHAR szModule[MAX_PATH];
		DWORD dwModulePathLength;
		if((dwModulePathLength = GetModuleFileNameW(hModule, szModule, MAX_PATH)) == 0)
		{
#ifdef _DEBUG
			OutputDebugString(L"[Main] Failed to get module path");
#endif
			return FALSE;
		}
		for(int i = dwModulePathLength - 1; i >= 0; i--)
		{
			if(szModule[i] == L'\\')
			{
				szModule[i] = L'\0';
				break;
			}
		}

		WCHAR szName[MAX_PATH];
		WCHAR debugstr[MAX_PATH];

		// 2. load emulating list from the same directory
		swprintf_s(szName, MAX_PATH, L"%s\\..\\emulating.txt", szModule);
		g_EmuList = new CEmuList(szName);
#ifdef _DEBUG
		OutputDebugString(L"[Main] Finished loading emulating list");
#endif

		// 3. load available list from the same directory
		swprintf_s(szName, MAX_PATH, L"%s\\..\\available.txt", szModule);
		g_AList = new CAvailableList(szName);
#ifdef _DEBUG
		OutputDebugString(L"[Main] Finished loading available list");
#endif

		// 4. load existing list from the same directory
		swprintf_s(szName, MAX_PATH, L"%s\\..\\existing.txt", szModule);
		g_ExtList = new CExtList(szName);
#ifdef _DEBUG
		OutputDebugString(L"[Main] Finished loading existing list");
#endif

		// 5. Create the emulator object
		CoInitialize(NULL);
		HRESULT result;
		result = CoGetClassObject(CLSID_COMEmu, CLSCTX_SERVER, NULL, IID_IClassFactory, (void **)&emuppv);
		if(FAILED(result)){
#ifdef _DEBUG
			swprintf_s(debugstr, MAX_PATH, L"[Main] Emulator ClassFactory Creation Error. Result Number: %0x", result);
			OutputDebugString(debugstr);
#endif
			return FALSE;
		}

		if(FAILED(emuppv ->lpVtbl ->CreateInstance(emuppv, NULL,IID_IDispatch, (void **)&emuIDispatch))){
#ifdef _DEBUG
			OutputDebugString(L"[Main] Emulator Instance Creation & IDispatch interface Error");
#endif
			return FALSE;
		}
		
		
		if(FAILED(emuIDispatch ->lpVtbl->QueryInterface(emuIDispatch, IID_IDispatchEx, (void**)&emuIDispatchEx)))
		{
#ifdef _DEBUG
			OutputDebugString(L"[Main] Emulator IDispatchEx interface Error");
#endif
			return FALSE;
		}
		swprintf_s(debugstr, MAX_PATH, L"[Main] Emulator IDispatchEx interface: %08x", emuIDispatchEx);
		OutputDebugString(debugstr);

		/*
		DISPID *ppid;
		ppid = new DISPID;
		result = emuIDispatchEx ->lpVtbl -> GetDispID(emuIDispatchEx, ::SysAllocString(L"CaptureActiveXServer2Hello"), fdexNameCaseSensitive, ppid);
		if(FAILED(result))
			OutputDebugString(L"[Main]!!!!!!!!!!!!!!!!!!!!!!!! failed GetDispID");
		*/

		// 6. hook COM library APIs
#ifdef _DEBUG
		OutputDebugString(L"[Main] Hook CoGetClassObject & CoCreateInstanceEx");
#endif

		//hHookDll = GetModuleHandle(L"MwSniffDll.dll");
/*
#if defined _INSPECTOR
		SendMsg = (SENDMSG)GetProcAddress(hHookDll, "SendMsg");
#endif
*/
		HookAPI("ole32.dll", "CoGetClassObject", MyCoGetClassObject, (PVOID *)&RealCoGetClassObject, SAFE_HOOKING);
		//HookAPI("ole32.dll", "CoCreateInstanceEx", MyCoCreateInstanceEx, (PVOID *)&OriginCoCreateInstanceEx, SAFE_HOOKING);
		HookAPI("ole32.dll", "CLSIDFromProgID", MyCLSIDFromProgID, (PVOID *)&RealCLSIDFromProgID, SAFE_HOOKING);
		OutputDebugString(L"Tiffany:Hooking finished");

		break;

	case DLL_PROCESS_DETACH:
		delete g_HookManager;
		delete g_AList;
#ifdef _DEBUG
		OutputDebugString(L"[Main] Unhook CoGetClassObject & CoCreateInstanceEx");
#endif

		//hHookDll = GetModuleHandle(L"MwSniffDll.dll");

		UnhookAPI((PVOID *)&RealCoGetClassObject);
		UnhookAPI((PVOID *)&CoCreateInstanceEx);
		UnhookAPI((PVOID *)&CLSIDFromProgID);

		OutputDebugString(L"[Main] Unhook complete");

		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}