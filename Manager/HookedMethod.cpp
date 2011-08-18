#include "stdafx.h"
#include "HookedMethod.h"
#include "HookManager.h"
#include "EmuList.h"
#include "COMEmu.h"


using namespace COMSniffer;

/// Global HookInfo manager
extern CHookManager *g_HookManager;
extern IClassFactory *emuppv;
extern IDispatch *emuIDispatch;
extern IDispatchEx *emuIDispatchEx;
extern CEmuList *g_EmuList;


///
/// \brief Callback function for IClassFactory::CreateInstance
///
/// This function monitors the creation of COM objects to:
///		1. notify MwDetector with object creation event;
///		2. hook the IDispatch interface of the created ActiveX control object.
/// 
/// \param[in] This This pointer to the IClassFactory interface of an object.
///	\param[in] pUnkOuter Not used, see MSDN for more info.
/// \param[in] riid Queried interface id (IID).
/// \param[out] ppvObject Pointer to save the queried interface pointer.
///	\return Query result.
/// \see MyCreateInstanceEx
///
HRESULT STDMETHODCALLTYPE MyCreateInstance(
	IClassFactory *This,
	IUnknown *pUnkOuter,
	REFIID riid,
	void **ppvObject
	)
{
	CIClassFactoryHookInfo *pInfo;
	HRESULT result, re;
	IDispatch *lpDispatch;
	IDispatchEx *lpDispatchEx;
	PVOID vtbl = ((IUnknown *)This)->lpVtbl;

#ifdef _DEBUG
	OLECHAR debugstr[200];
	LPOLESTR clsid, iid;
#endif

#ifdef _DEBUG
	swprintf_s(debugstr, 200, L"[IClassFactory::MyCreateInstance] gonna CHookManager::Find: object %08x, vtable: %08x", This, vtbl);
	OutputDebugString(debugstr);
#endif
	// 1. get the corresponding HookInfo of the IClassFactory using This pointer
	if((pInfo = (CIClassFactoryHookInfo *)g_HookManager->Find(This)) == NULL)
		return E_FAIL;
	if(pUnkOuter == NULL)
		OutputDebugString(L"pUnkOuter is NULL");
#ifdef _DEBUG
	StringFromCLSID(pInfo->GetCLSID(This), &clsid);
	StringFromIID(riid, &iid);
	swprintf_s(debugstr, 200, L"[IClassFactory::MyCreateInstance] object with CLSID %s IID %s created", clsid, iid);
	OutputDebugString(debugstr);
	CoTaskMemFree(iid);
	CoTaskMemFree(clsid);
#endif

	// 2. call the original method
	result = pInfo->CreateInstance(This, pUnkOuter, riid, ppvObject);
	if(FAILED(result)) //FIXME log the error reason
		goto ERROR_ABORT;

#ifdef _DEBUG
	StringFromCLSID(pInfo->GetCLSID(This), &clsid);
	StringFromIID(riid, &iid);
	swprintf_s(debugstr, 200, L"[IClassFactory::MyCreateInstance] object %08x with CLSID %s IID %s created", *ppvObject, clsid, iid);
	OutputDebugString(debugstr);
	CoTaskMemFree(iid);
	CoTaskMemFree(clsid);
#endif

	// 3. check if the given iid is not IID_IDispatch
	if(!IsEqualIID(riid, IID_IDispatch))
	{
#ifdef _DEBUG
		OutputDebugString(L"[IClassFactory::MyCreateInstance] object is NOT Created by IDispatch, it is IUnknown");
#endif

		// 3.0 if not, check if this component supports IDispatchEx interface
		re = ((IUnknown *)(*ppvObject))->lpVtbl->QueryInterface((IUnknown *)(*ppvObject), IID_IDispatchEx, &(PVOID&)lpDispatchEx);
		
		// if it doesn't support, do not handle such objects now
		if(FAILED(re))
			OutputDebugString(L"[IClassFactory::MyCreateInstance]=================No IDispatchEx, where comes GetIdsFromNames then??==========");
		else{
			OutputDebugString(L"[IClassFactory::MyCreateInstance]IDispatchEx!!");
			
		}
		// 3.1 if not, check if this component supports IDispatch interface
		re = ((IUnknown *)(*ppvObject))->lpVtbl->QueryInterface((IUnknown *)(*ppvObject), IID_IDispatch, &(PVOID&)lpDispatch);

		// if it doesn't support, do not handle such objects now
		if(FAILED(re))
			goto ERROR_ABORT;

			
	}
	else
	{
		// 3.2 if is, copy the interface pointer
		lpDispatch = (IDispatch *)(*ppvObject);
		lpDispatch->lpVtbl->AddRef(lpDispatch);
	}

#ifdef _DEBUG
	OutputDebugString(L"[IClassFactory::MyCreateInstance]object supports IDispatch");
#endif

	// 4. get the component's clsid
	REFCLSID rclsid = pInfo->GetCLSID(This);


#ifdef _DEBUG
	OutputDebugString(L"[IClassFactory::MyCreateInstance]Gonna addRef to this IDispatch");
#endif
	
	// 5. add reference
	if((PVOID *)lpDispatch == (PVOID *)lpDispatchEx)
		OutputDebugString(L"!!!!!!dispatch ====== dipatchex");
	//g_HookManager->AddRef(lpDispatch, rclsid); //FIXME check result
	g_HookManager->AddRef(lpDispatchEx, rclsid);
	// 6. release the queried or copied interface
	lpDispatch->lpVtbl->Release(lpDispatch);

ERROR_ABORT:
	return result;
}

HRESULT STDMETHODCALLTYPE MyQueryInterface(IDispatch *This, REFIID riid, void **ppvObject)
{
	CIDispatchHookInfo *pInfo;
	HRESULT result;
#ifdef _DEBUG
	OLECHAR debugstr[200];
	LPOLESTR iid;
	IDispatchVtbl *thisvtbl = This->lpVtbl;
#endif

#ifdef _DEBUG
	StringFromIID(riid, &iid);
	swprintf_s(debugstr, 200, L"IDispatch::MyQueryInterface: IID %s in vtable: %08x", iid, thisvtbl);
	OutputDebugString(debugstr);
	CoTaskMemFree(iid);
#endif
	
	pInfo = (CIDispatchHookInfo *)g_HookManager->Find(This);
	if(pInfo == NULL)
		return E_FAIL;
	//real QueryInterface
	result = pInfo->QueryInterface(This, riid, ppvObject);
	if(FAILED(result)){
#ifdef _DEBUG	
	//	swprintf_s(debugstr, 200, L"QueryInterface found: vtable: %08x", vtbl);
		StringFromIID(riid, &iid);
		swprintf_s(debugstr, 200, L"QueryInterface NOT found: IID%s", iid);
		OutputDebugString(debugstr);
		CoTaskMemFree(iid);
#endif
		return result;
	}
	IDispatchVtbl *vtbl = ((IDispatch *)(*ppvObject))->lpVtbl;
	IDispatchExVtbl *lpVtbl = ((IDispatchEx *)(*ppvObject))->lpVtbl;
#ifdef _DEBUG	
//	swprintf_s(debugstr, 200, L"QueryInterface found: vtable: %08x", vtbl);
	StringFromIID(riid, &iid);
	swprintf_s(debugstr, 200, L"QueryInterface found: IID%s, vtable: %08x", iid, lpVtbl);
	OutputDebugString(debugstr);
	CoTaskMemFree(iid);
#endif
	if(IsEqualIID(riid, IID_IDispatch))
		OutputDebugString(L"iid is IDispatch");
	if(*ppvObject != This && IsEqualIID(riid, IID_IDispatch))
	{
		g_HookManager->AddRef(((IDispatch *)(*ppvObject)), pInfo->GetCLSID(This));
	}

	return result;
}

HRESULT STDMETHODCALLTYPE MyFQueryInterface(IClassFactory *This, REFIID riid, void **ppvObject)
{
	CIClassFactoryHookInfo *pInfo;
	HRESULT result;
#ifdef _DEBUG
	OLECHAR debugstr[200];
	LPOLESTR iid;
#endif

#ifdef _DEBUG
	StringFromIID(riid, &iid);
	swprintf_s(debugstr, 200, L"IClassFactory::MyFQueryInterface: IID %s %08x", iid, This);
	OutputDebugString(debugstr);
	CoTaskMemFree(iid);
#endif

	if((pInfo = (CIClassFactoryHookInfo *)g_HookManager->Find(This)) == NULL)
		return E_FAIL;

	result = pInfo->QueryInterface(This, riid, ppvObject);
	if(FAILED(result))
		return result;

	if(*ppvObject != This && IsEqualIID(riid, IID_IClassFactory))
	{
		g_HookManager->AddRef(((IClassFactory *)(*ppvObject)), pInfo->GetCLSID(This));
	}

	return result;
}

///
/// \brief Callback function for IDispatch::Release
///
/// This function monitors the free of automation (ActiveX) objects to:
///		1. notify MwDetector with object free event;
///		2. notify the HookManager a object has been freed, if all objects with the same CLSID have been freed,
///        the HookManager unhooks the IDispatch interface of the this ActiveX control.
/// 
/// \param[in] This This pointer to the IDispatch interface of an object.
///	\return Release result.
///
ULONG STDMETHODCALLTYPE MyRelease(IDispatch *This)
{
	CIDispatchHookInfo *pInfo;
	ULONG result;

	PVOID vtbl = This->lpVtbl;

#ifdef _DEBUG
	OLECHAR debugstr[200];
#endif

#ifdef _DEBUG
	swprintf_s(debugstr, 200, L"Tiffany: IDispatch::MyRelease Vtable : %08x", vtbl);
	OutputDebugString(debugstr);
#endif

	// 1. get the corresponding HookInfo using This pointer
#ifdef _DEBUG
	OutputDebugString(L"Tiffany: IDispatch::MyRelease goto g_hookmanager -> Find");
#endif
	if((pInfo = (CIDispatchHookInfo *)g_HookManager->Find(This)) == NULL)
		return 0;

	// 2. call the original method
	result = pInfo->Release(This);

	// 3. if the original method returns 0
	if(result == 0)
	{
#ifdef _DEBUG
		OutputDebugString(L"MyRelease: object count decreased to 0");
#endif

		// 3.1 notify detection module with object free event
		//g_DtProxy->OnObjectRelease(This);

		// 3.2 tell HookManager to decrease the reference
		g_HookManager->Release(pInfo, This, vtbl);
	}

	return result;
}

///
/// \brief Callback function for IClassFactory::Release
///
/// This function monitors the free of factory objects to:
///		1. notify the HookManager a object has been freed, if all objects with the same CLSID have been freed,
///        the HookManager unhooks the IClassFactory interface of the this ActiveX control.
/// \param[in] This This pointer to the IClassFactory interface of an object.
///	\return Release result.
/// \see MyRelease
///
ULONG STDMETHODCALLTYPE MyFRelease(IClassFactory *This)
{
	CIClassFactoryHookInfo *pInfo;
	ULONG result;

	PVOID vtbl = This->lpVtbl;

#ifdef _DEBUG
	OutputDebugString(L"Tiffany: MyFRelease, goto g_hookmanager -> Find");
#endif
	if((pInfo = (CIClassFactoryHookInfo *)g_HookManager->Find(This)) == NULL)
		return 0;
	result = pInfo->Release(This);
#ifdef _DEBUG
	LPOLESTR clsid;
	OLECHAR debugstr[200];
	REFCLSID rclsid = pInfo->GetCLSID(This);
	StringFromCLSID(pInfo->GetCLSID(This), &clsid);
	swprintf_s(debugstr, L"--------------------------MyFRelease clsid: %s, result is %d", clsid, result);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif
	if(result < 0)
	{
#ifdef _DEBUG
		OutputDebugString(L"MyFRelease: object count decreased BELOW to 0");
#endif
	}
	else if(result == 0){
#ifdef _DEBUG
		OutputDebugString(L"MyFRelease: object count decreased to 0");
#endif
		g_HookManager->Release(pInfo, This, vtbl);
	}

	return result;
}

///
/// \brief Callback function for IDispatch::GetIDsOfNames
///
/// This function monitors the invocation to GetIDsOfName to get the MethodName <-> DispatchID (DispID)
/// and save them in HookInfo. 
/// The method name and corresponding id are always stored as the first element in the array.
/// 
/// \param[in] This This pointer to the IDispatch interface of an object.
/// \param[in] riid Not used, reserved by Microsoft.
///	\param[in] rgszNames Array of queried names.
/// \param[in] cNames Number of queried names.
/// \param[in] lcid Not used, locale context, see MSDN for more info.
/// \param[out] rgDispID Caller-allocated array to save returned DispIDs.
///	\return Query result.
///
HRESULT STDMETHODCALLTYPE MyGetIDsOfNames(
	IDispatch *This,
	REFIID riid,
	LPOLESTR *rgszNames,
	UINT cNames,
	LCID lcid,
	DISPID *rgDispId
	)
{
	CIDispatchHookInfo *pInfo;
#ifdef _DEBUG
	OLECHAR debugstr[200];
	LPOLESTR clsid;
#endif

#ifdef _DEBUG
	OutputDebugString(L"MyGetIDsOfNames");
	//for(UINT i = 0; i < cNames; i++)
	//{
	//	OutputDebugString(rgszNames[0i]);
	//}
#endif

	// 1. get the corresponding HookInfo using This pointer
	if((pInfo = (CIDispatchHookInfo *)g_HookManager->Find(This)) == NULL)
		return E_FAIL;

	// 2. call the original method
	HRESULT result = pInfo->GetIDsOfNames(This, riid, rgszNames, cNames, lcid, rgDispId);
	if(FAILED(result)) //FIXME log the error reason
	{
#ifdef _DEBUG
		OutputDebugString(L"Original GetIDsOfNames failed");
#endif
		return result;
	}

	// check if there is any error
	//for(UINT i = 0; i < cNames; i++)
	//{
	//	// if error occurs
	//	if(rgDispId[0] < 0)
	//		return result;
	//}

#ifdef _DEBUG
	StringFromCLSID(pInfo->GetCLSID(This), &clsid);
	swprintf_s(debugstr, 200, L"MyGetIDsOfNames clsid: %s, Name: %s, ID: %d", clsid, rgszNames[0], rgDispId[0]);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif

	// 3. add the DISPID-Name pair to HookInfo
	// method name is given as the first element of the names array
	pInfo->AddDispID(This, rgDispId[0], rgszNames[0]);

	return result;
}

///
/// \brief Callback function for IDispatch::Invoke
///
/// This function monitors the invocation to Invoke to notify MwDetector with method invocation event.
/// 
/// \param[in] This This pointer to the IDispatch interface of an object.
/// \param[in] dispIdMember Dispatch ID of the method to invoke.
/// \param[in] riid Not used, reserved by Microsoft.
/// \param[in] lcid Not used, locale context, see MSDN for more info.
/// \param[in] wFlags Context of the invoke, e.g. DISPATCH_METHOD, DISPATCH_PROPERTYGET.
///	\param[in] pDispParams Parameters information.
/// \param[out] pVarResult Not used, result of the invocation, could be NULL.
/// \param[out] pExcepInfo Not used, exception info of the invocation, could be NULL.
/// \param[out] puArgErr Not used, index of the augument that causes the error.
///	\return Invocation result.
///
HRESULT STDMETHODCALLTYPE MyInvoke(
	IDispatch *This,
	DISPID dispIdMember,
	REFIID riid,
	LCID lcid,
	WORD wFlags,
	DISPPARAMS *pDispParams,
	VARIANT *pVarResult,
	EXCEPINFO *pExcepInfo,
	UINT *puArgErr
	)
{
	CIDispatchHookInfo *pInfo;
	
#ifdef _DEBUG
	LPOLESTR clsid;
	OLECHAR debugstr[200];
#endif

#ifdef _DEBUG
	OutputDebugString(L"MyInvoke");
#endif

	// 1. get the corresponding HookInfo using This
	if((pInfo = (CIDispatchHookInfo *)g_HookManager->Find(This)) == NULL)
		return E_FAIL;

#ifdef _DEBUG
	StringFromCLSID(pInfo->GetCLSID(This), &clsid);
	swprintf_s(debugstr, 200, L"MyInvoke clsid: %s, ID: %d, Flags: %08x", clsid, dispIdMember, wFlags);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif

	// 2. get the method name
	BSTR method = pInfo->FindDispID(This, dispIdMember);
	if(method == NULL)
		goto ERROR_ABORT;

#ifdef _DEBUG
	OutputDebugString(method);
#endif

	/*
	// 3. check if the invocation is an attack
	if(g_DtProxy->OnMethodCalling(This, pInfo->GetCLSID(This), method, wFlags, pDispParams) == STATUS_ATTACK)
	{
#ifdef _DEBUG
		OutputDebugString(L"ATTACK DETECTED");
#endif
		// 4. if it is, send the information to MwSniffer via IPC
		SendAlert(pInfo->GetCLSID(This), method, pDispParams);

		// do not block the attack due to unreliable IPC
		return S_OK;
	}
	

	// 5. if no attack is detected, send the invocation info to MwSniffer
	SendInvocation(pInfo->GetCLSID(This), method, pDispParams);
	*/

ERROR_ABORT:

	// 6. call the original method
	HRESULT result = pInfo->Invoke(This,
		dispIdMember,
		riid,
		lcid,
		wFlags,
		pDispParams,
		pVarResult,
		pExcepInfo,
		puArgErr
		);

	return result;
}

HRESULT  STDMETHODCALLTYPE MyGetDispID(
	IDispatchEx *This,
	BSTR bstrName,
	DWORD grfdex,
	DISPID *pid
	)
{
	CIDispatchExHookInfo *pInfo;
	BSTR hookname;
	HRESULT result = TRUE;
	OLECHAR Methodstr[200], ProgStr[200];
	BSTR bstrText;
	//CComBSTR a;
#ifdef _DEBUG
	OLECHAR debugstr[200];
	LPOLESTR clsid;
#endif

#ifdef _DEBUG
	swprintf_s(debugstr, 200, L"[IDispatchEx::MyGetDispID] GetDispID This interface: %08x, grfdex %0x", This, grfdex);
	OutputDebugString(debugstr);
#endif
	if(This == emuIDispatchEx){
		if((pInfo = (CIDispatchExHookInfo *)g_HookManager->Find(This)) == NULL)
			return E_FAIL;
		swprintf_s(debugstr, 200, L"[IDispatchEx::MyGetDispID] GetDispID for emulator, Method Name %s", bstrName);
		OutputDebugString(debugstr);
		//bstrText = ::SysAllocString(L"Helloabc");
		result = pInfo ->GetDispID(emuIDispatchEx, bstrName, grfdex, pid);
		if(FAILED(result))
			OutputDebugString(L"[IDispatchEx::MyGetDispID] failed original call");
		return result;
	}
	else
	{
		if((pInfo = (CIDispatchExHookInfo *)g_HookManager->Find(This)) == NULL)
			return E_FAIL;
#ifdef _DEBUG
		OutputDebugString(L"[IDispatchEx::MyGetDispID] Hooked before, continue");
#endif	

		REFCLSID rclsid = pInfo->GetCLSID(This);
#ifdef _DEBUG
		OutputDebugString(L"[IDispatchEx::MyGetDispID] Goto GetHookName");
#endif
		hookname = ::SysAllocString(L"");
		g_EmuList -> GetHookName(rclsid, hookname);
		//re = ProgIDFromCLSID(rclsid, &progid);

		//StringFromCLSID(pInfo->GetCLSID(This), &clsid);
		
		OutputDebugString(L"[IDispatchEx::MyGetDispID] Exit GetHookName");
		OutputDebugString(hookname);
		
		swprintf_s(Methodstr, 200, L"%s%s", hookname, bstrName);
		/*
		int s = wcslen(ProgStr);
		int j = 0;
		for(int i = 0; i < s; i++)
			if(ProgStr[i] != '.' && ProgStr[i] != ' ')
				Methodstr[j++] = ProgStr[i];
			
		swprintf_s(&Methodstr[j], 199 - j, L"%s", bstrName);
		*/
		//bstrText = ::SysAllocString(L"Helloabc");	
		bstrText = ::SysAllocString(Methodstr);
		OutputDebugString(Methodstr);
		//CoTaskMemFree(clsid);
		
		/*
		if(FAILED(emuIDispatchEx ->lpVtbl ->GetDispID(emuIDispatchEx, bstrText, grfdex, pid)))
		{
	#ifdef _DEBUG
			OutputDebugString(L"[IDispatch::MyGetDispID] Emulator GetDispID failed");
	#endif
			result = FALSE;
		}
		*/
		OutputDebugString(L"[IDispatchEx::MyGetDispID] Before calling emulator");
		if(emuIDispatchEx == NULL)
				OutputDebugString(L"Something wrong with emulator");
		result = emuIDispatchEx ->lpVtbl ->GetDispID(emuIDispatchEx, bstrText, grfdex, pid);
		OutputDebugString(L"[IDispatchEx::MyGetDispID] After calling emulator");
		if(FAILED(result))
			OutputDebugString(L"[IDispatchEx::GetDispID] failed original call");
#ifdef _DEBUG
		StringFromCLSID(pInfo->GetCLSID(This), &clsid);
		swprintf_s(debugstr, L"[IDispatchEx::GetDispID] MyGetDispID clsid: %s, Name: %s, ID: %d, gonna AddDispID", clsid, bstrName, *pid);
		OutputDebugString(debugstr);
		CoTaskMemFree(clsid);
#endif

		pInfo->AddDispID(This, *pid, bstrName);

		return result;
	}
}

HRESULT STDMETHODCALLTYPE MyInvokeEx( 
    IDispatchEx * This,
    /* [in] */ DISPID id,
    /* [in] */ LCID lcid,
    /* [in] */ WORD wFlags,
    /* [in] */ DISPPARAMS *pdp,
    /* [out] */ VARIANT *pVarRes,
    /* [out] */ EXCEPINFO *pei,
    /* [unique][in] */ IServiceProvider *pspCaller
	)
{
	CIDispatchExHookInfo *pInfo;
	
#ifdef _DEBUG
	LPOLESTR clsid;
	OLECHAR debugstr[200];
#endif

#ifdef _DEBUG
	OutputDebugString(L"[IDispatchEx::InvokeEx]");
#endif

	// 1. get the corresponding HookInfo using This
	if((pInfo = (CIDispatchExHookInfo *)g_HookManager->Find(This)) == NULL)
		return E_FAIL;
#ifdef _DEBUG
	StringFromCLSID(pInfo->GetCLSID(This), &clsid);
	swprintf_s(debugstr, 200, L"[IDispatchEx::InvokeEx] clsid: %s, ID: %d, Flags: %08x", clsid, id, wFlags);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif

	// 2. get the method name
	BSTR method = pInfo->FindDispID(This, id);
	if(method == NULL)
		goto ERROR_ABORT;

#ifdef _DEBUG
	OutputDebugString(method);
#endif


ERROR_ABORT:
#ifdef _DEBUG
	OutputDebugString(L"[IDispatchEx::InvokeEx] Invoke the original method BEGIN");
#endif

	// 3. call the original method
	HRESULT result = pInfo->InvokeEx(emuIDispatchEx, 
		id, 
		lcid,
		wFlags,
		pdp,
		pVarRes,
		pei,
		pspCaller
		);
	
#ifdef _DEBUG
	OutputDebugString(L"[IDispatchEx::InvokeEx] Invoke the original method OVER");
#endif

	return result;

}
