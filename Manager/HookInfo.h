#pragma once

#include <ole2.h>
#include <dispex.h>
#include <map>
#include<ServProv.h>

using std::map;

namespace COMSniffer
{
	class CBaseHookInfo
	{
	public:
		CBaseHookInfo() {m_Ref = 0; m_clsid = CLSID_NULL; m_vtbl = NULL; InitializeCriticalSection(&m_cs);};
		CBaseHookInfo(REFCLSID rclsid, PVOID vtbl);
		virtual ~CBaseHookInfo() {};

		LONG AddRef(const PVOID object, REFCLSID clsid, BOOLEAN locked);
		LONG Release(const PVOID object, BOOLEAN locked);

		CLSID GetCLSID(const PVOID object);
	
	protected:
		CLSID m_clsid;
		LONG m_Ref;
		PVOID m_vtbl;

		map<PVOID, CLSID> m_objects;
		CRITICAL_SECTION m_cs;
	};


	class CIDispatchHookInfo : public CBaseHookInfo
	{
	public:
		CIDispatchHookInfo() {QueryInterface = NULL; Release = NULL; GetIDsOfNames = NULL; Invoke = NULL; InitializeCriticalSection(&MethodCS);};
		CIDispatchHookInfo(REFCLSID rclsid, IDispatchVtbl *vtbl);
		virtual ~CIDispatchHookInfo();

		HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDispatch * This, REFIID riid, void **ppvObject);
		ULONG (STDMETHODCALLTYPE *Release)(IDispatch * This);

		HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)(
			IDispatch * This,
			REFIID riid,
			LPOLESTR *rgszNames,
			UINT cNames,
			LCID lcid,
			DISPID *rgDispId
			);
		HRESULT (STDMETHODCALLTYPE *Invoke)(
			IDispatch * This,
			DISPID  dispIdMember,
			REFIID  riid,
			LCID  lcid,
			WORD  wFlags,
			DISPPARAMS *pDispParams,
			VARIANT *pVarResult,
			EXCEPINFO *pExcepInfo,
			UINT *puArgErr
			);

		BOOLEAN AddDispID(const PVOID object, DISPID dispID, OLECHAR *szName);
		BSTR FindDispID(const PVOID, DISPID dispID);

	protected:
		std::map<PVOID, map<DISPID, BSTR> > Methods;
		CRITICAL_SECTION MethodCS;
	};

	class CIDispatchExHookInfo : public CBaseHookInfo
	{
	public:
		CIDispatchExHookInfo() {QueryInterface = NULL; Release = NULL; GetDispID = NULL; 
		InvokeEx = NULL; 
		InitializeCriticalSection(&MethodCS);};
		CIDispatchExHookInfo(REFCLSID rclsid, IDispatchExVtbl *vtbl);
		virtual ~CIDispatchExHookInfo();

		HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDispatchEx * This, REFIID riid, void **ppvObject);
		ULONG (STDMETHODCALLTYPE *Release)(IDispatchEx * This);
		HRESULT (STDMETHODCALLTYPE *GetDispID)(
			IDispatchEx * This,
			BSTR bstrName,
			DWORD grfdex,
			DISPID *pid
			);
		HRESULT (STDMETHODCALLTYPE *InvokeEx)(
			IDispatchEx * This,
			DISPID id,
			LCID lcid,
			WORD wFlags,
			DISPPARAMS *pdp,
			VARIANT *pVarRes, 
			EXCEPINFO *pei, 
			IServiceProvider *pspCaller 
			);

		BOOLEAN AddDispID(const PVOID object, DISPID dispID, OLECHAR *szName);
		BSTR FindDispID(const PVOID, DISPID dispID);

	protected:
		std::map<PVOID, map<DISPID, BSTR> > Methods;
		CRITICAL_SECTION MethodCS;
	};

	class CIClassFactoryHookInfo : public CBaseHookInfo
	{
	public:
		CIClassFactoryHookInfo() {QueryInterface = NULL; Release = NULL; CreateInstance = NULL;};
		CIClassFactoryHookInfo(REFCLSID rclsid, IClassFactoryVtbl *vtbl);
		virtual ~CIClassFactoryHookInfo();

		HRESULT (STDMETHODCALLTYPE *QueryInterface)(IClassFactory * This, REFIID riid, void **ppvObject);
		ULONG (STDMETHODCALLTYPE *Release)(IClassFactory * This);

		HRESULT (STDMETHODCALLTYPE *CreateInstance)(
			IClassFactory * This,
			IUnknown *pUnkOuter,
			REFIID riid,
			void **ppvObject
			);
	};
	
};
