#include <ole2.h>
#include <dispex.h>

HRESULT STDMETHODCALLTYPE MyQueryInterface(IDispatch *This, REFIID riid, void **ppvObject);
ULONG STDMETHODCALLTYPE MyRelease(IDispatch *This);

HRESULT STDMETHODCALLTYPE MyFQueryInterface(IClassFactory *This, REFIID riid, void **ppvObject);
ULONG STDMETHODCALLTYPE MyFRelease(IClassFactory *This);

HRESULT STDMETHODCALLTYPE MyCreateInstance(
	IClassFactory *This,
	IUnknown *pUnkOuter,
	REFIID riid,
	void **ppvObject
	);

HRESULT STDMETHODCALLTYPE MyGetIDsOfNames(
	IDispatch * This,
	REFIID riid,
	LPOLESTR *rgszNames,
	UINT cNames,
	LCID lcid,
	DISPID *rgDispId
	);

HRESULT STDMETHODCALLTYPE MyInvoke(
	IDispatch * This,
	DISPID dispIdMember,
	REFIID riid,
	LCID lcid,
	WORD wFlags,
	DISPPARAMS *pDispParams,
	VARIANT *pVarResult,
	EXCEPINFO *pExcepInfo,
	UINT *puArgErr
	);

HRESULT STDMETHODCALLTYPE MyGetDispID(
	IDispatchEx *This,
	BSTR bstrName,
	DWORD grfdex,
	DISPID *pid
	);


HRESULT STDMETHODCALLTYPE MyInvokeEx( 
    IDispatchEx * This,
    /* [in] */ DISPID id,
    /* [in] */ LCID lcid,
    /* [in] */ WORD wFlags,
    /* [in] */ DISPPARAMS *pdp,
    /* [out] */ VARIANT *pVarRes,
    /* [out] */ EXCEPINFO *pei,
    /* [unique][in] */ IServiceProvider *pspCaller
	);