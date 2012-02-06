#include "stdafx.h"
#include "HookedMethod.h"
#include "HookManager.h"
#include "EmuList.h"
#include "COMEmu.h"
#include <iostream>
#include <fstream>
#include <time.h>
#include <stdint.h>
#include <cstring>
#include <string.h>
#include <sstream>
#include <cstdio>
//#include <atlstr.h>
//#include <atlconv.h>
using namespace COMSniffer;
using namespace std;

#define FUZZINPUT "C:\\fuzzOutput.log"
#define AXMOCKOUTPUT "C:\\Axmock_TA.log"
#define CONFIRMOUTPUT "C:\\confirm.log"
/// Global HookInfo manager
extern CHookManager *g_HookManager;
extern IClassFactory *emuppv, *recppv;
extern IDispatch *emuIDispatch, *recIDispatch;
extern IDispatchEx *emuIDispatchEx, *recIDispatchEx;
extern CEmuList *g_EmuList;
extern DISPID recParamDisp[20];
//extern std::ofstream axmockOutput;
extern int invokeCount;

char* ConvertBSTRToLPSTR (BSTR bstrIn)
{
  LPSTR pszOut = NULL;
  if (bstrIn != NULL)
  {
	int nInputStrLen = SysStringLen (bstrIn);

	// Double NULL Termination
	int nOutputStrLen = WideCharToMultiByte(CP_ACP, 0, bstrIn, nInputStrLen, NULL, 0, 0, 0) + 2; 
	pszOut = new char [nOutputStrLen];

	if (pszOut)
	{
	  memset (pszOut, 0x00, sizeof (char)*nOutputStrLen);
	  WideCharToMultiByte (CP_ACP, 0, bstrIn, nInputStrLen, pszOut, nOutputStrLen, 0, 0);
	}
  }
  return pszOut;
}

BSTR ConvertLPSTRToBSTR (LPSTR pszIn){
	OLECHAR debugstr[MAX_PATH];
	int charLen = strlen(pszIn) + 1;
	int wcharLen = MultiByteToWideChar(CP_ACP, 0, pszIn, charLen, NULL, 0);
	WCHAR *wcharOut;
	wcharOut = new WCHAR[wcharLen];
	MultiByteToWideChar(CP_ACP, 0, pszIn, charLen, wcharOut, wcharLen);
	swprintf_s(debugstr, MAX_PATH, L"[ConverLPSTRToBSTR] the legth of char* is %d, wchar* is %d", charLen, wcharLen);
	OutputDebugString(debugstr);
	
	BSTR bstrOut;
	bstrOut = ::SysAllocString(wcharOut);
	swprintf_s(debugstr, MAX_PATH, L"[ConverLPSTRToBSTR] the legth of bstrOut is %d", ::SysStringLen(bstrOut));
	OutputDebugString(debugstr);
	return bstrOut;
}
char hexchar(int x) {
  if(x < 10) return (char)('0' + x);
  return (char)('A' + (x-10));
}

string hex(unsigned char o) {
  //cout << "hex(" << o << ")=";
  stringstream ss;
  ss << "\\x" << hexchar(o/16) << hexchar(o%16);
  //cout << ss.str() << endl;
  return ss.str();
}

int dec(unsigned char o){
	if (o >= '0' && o <= '9') return o - '0';
	else return 10 + (o - 'a');
}

string encode(char* s, int len) {
  OLECHAR debugstr[MAX_PATH];
  swprintf_s(debugstr, MAX_PATH, L"[encode] length is %d, length of char is %d", len, strlen(s));
  OutputDebugString(debugstr);
  
  string res = "";

  for(int i = 0; i < len; i++){
	if(s[i] == '\\') {
		res = res + "\\\\"; /* heng! */
	}
	//NOTICE: CANNOT USE isprint here, don't know why
	else if((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) {
		res = res + s[i];
	}
	else{
		res = res + hex(s[i]);
	}
	
  }
  //swprintf_s(debugstr, MAX_PATH, L"[encode] result is %s", res);
  //OutputDebugString(debugstr);
  
  return res;
}


int decode(string s, char *ss){
	int len = 0, i = 0;
	OutputDebugString(L"[decode] Continue");
	while(i < (int) s.length()){
		if(s[i] == '\\'){
			if(s[i+1] == 'x' || s[i+1] == 'X'){
				ss[len] = (char) (dec(s[i+2]) * 16 + dec(s[i+3]));
				i += 3;
			}
			else if(s[i+1] == '\\'){ss[len] = '\\'; i++;}
		}
		else ss[len] = s[i];
		i++;
		len++;
	}
	return 0;
}
bool IsEqualBSTR_CHAR(BSTR bstr, char* char_array){
	OLECHAR debugstr[MAX_PATH];
	char *bstr_convert = ConvertBSTRToLPSTR(bstr);
	swprintf_s(debugstr, MAX_PATH, L"%d, %d", strlen(bstr_convert), strlen(char_array));
	OutputDebugString(debugstr);
	if(strlen(char_array) > 700){
		swprintf_s(debugstr, MAX_PATH, L"bstr_convert[600] is %c, char_array[600] is %c", bstr_convert[600], char_array[600]);
		OutputDebugString(debugstr);
	}

	//if(strcmp(bstr_convert, char_array)==0){
	if(strlen(bstr_convert) == strlen(char_array)){
		OutputDebugString(L"[IsEqualBSTR] Equal!");
		return 1;
	}
	else return 0;
}
int OutParameter(VARIANTARG &arg, std::ofstream &outputFile){
	switch(arg.vt){
		case VT_BSTR:{
			//outputFile << "Address: " << arg << std::endl;
			outputFile << "Type: BSTR" << std::endl;
			BSTR *addrs;
			addrs = &(arg.bstrVal);
			outputFile << "bstrVal Address: " << (arg.bstrVal) << std::endl;
			outputFile << "addrs:" << addrs << std::endl;
			outputFile << "length: " << ::SysStringLen(arg.bstrVal) << std::endl;
			outputFile << ConvertBSTRToLPSTR(arg.bstrVal) << std::endl;
			outputFile << "end address:" << arg.bstrVal + ::SysStringLen(arg.bstrVal) * sizeof(BSTR) << std::endl;
			outputFile.flush();
			break;
					 }
		default:
			OutputDebugString(L"[OutputParameter] No type found");
			break;
	}
	return 0;
}
int OutputParameter2(VARIANTARG &arg, std::ofstream &outputFile){
	//type
	outputFile << arg.vt << std::endl;
	int bstrLength;
	switch(arg.vt){
		case VT_BSTR:
			// number of type BSTR is 8
			// start Address, end Address, value, length
			bstrLength = (int)::SysStringLen(arg.bstrVal);
			outputFile << arg.bstrVal << std::endl;
			outputFile << arg.bstrVal + ::SysStringLen(arg.bstrVal) * sizeof(BSTR) << std::endl;
			//outputFile << encode(ConvertBSTRToLPSTR(arg.bstrVal), bstrLength) << std::endl;
			//outputFile << bstrLength << std::endl;
			//outputFile.flush();
			break;
		case VT_I2:
			outputFile << &arg.iVal << std::endl;
			outputFile << &arg.iVal + sizeof(short) << std::endl;
			//outputFile << arg.iVal << std::endl;
			//outputFile.flush();
			break;
		case VT_I4:
			outputFile << &arg.lVal << std::endl;
			outputFile << &arg.lVal + sizeof(long) << std::endl;
			//outputFile << arg.lVal << std::endl;
			break;
		case VT_R4:
			outputFile << &arg.fltVal << std::endl;
			outputFile << &arg.fltVal + sizeof(FLOAT) << std::endl;
			//outputFile << arg.fltVal << std::endl;
			break;
		case VT_DISPATCH:
			//pdispVal is Idispatch*
			outputFile << &arg.pdispVal << std::endl;
		case VT_EMPTY:
			outputFile << "EMPTY" << std::endl;
			break;
		default:
			OutputDebugString(L"[OutputParameter2] NO TYPE FOUND!!!");
			break;
	}
	outputFile << flush;
	return 0;
}
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
	bool hookEx;
#ifdef _DEBUG
	OLECHAR debugstr[MAX_PATH];
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
		OutputDebugString(L"[IClassFactory::MyCreateInstance] pUnkOuter is NULL");

	
	// 2. call the original method
	result = pInfo->CreateInstance(This, pUnkOuter, riid, ppvObject);
	if(This == recppv){
		*ppvObject = *((void **)&recIDispatch);
#ifdef _DEBUG
		OutputDebugString(L"[IClassFactory::MyCreateInstance] Recorder's Class Factory");
#endif

	}

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
		hookEx = false;
		if(FAILED(re)){
			OutputDebugString(L"[IClassFactory::MyCreateInstance]=================No IDispatchEx, where comes GetIdsFromNames then??==========");
		}
		else{
			hookEx = true;
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
	OutputDebugString(L"[IClassFactory::MyCreateInstance] Object supports IDispatch");
#endif

	// 4. get the component's clsid
	REFCLSID rclsid = pInfo->GetCLSID(This);


#ifdef _DEBUG
	OutputDebugString(L"[IClassFactory::MyCreateInstance] Gonna addRef to this IDispatch");
#endif
	
	// 5. add reference
	
	if(hookEx)
		g_HookManager->AddRef(lpDispatchEx, rclsid);
	else
		g_HookManager->AddRef(lpDispatch, rclsid); //FIXME check result
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
	OLECHAR debugstr[MAX_PATH];
	LPOLESTR iid;
	IDispatchVtbl *thisvtbl = This->lpVtbl;
#endif

#ifdef _DEBUG
	StringFromIID(riid, &iid);
	swprintf_s(debugstr, 200, L"[IDispatch::MyQueryInterface] IID %s in vtable: %08x", iid, thisvtbl);
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
	//IDispatchVtbl *vtbl = ((IDispatch *)(*ppvObject))->lpVtbl;
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
	OLECHAR debugstr[MAX_PATH];
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
	OLECHAR debugstr[MAX_PATH];
#endif

#ifdef _DEBUG
	swprintf_s(debugstr, 200, L"[IDispatch::MyRelease] Vtable : %08x", vtbl);
	OutputDebugString(debugstr);
#endif

	// 1. get the corresponding HookInfo using This pointer
#ifdef _DEBUG
	OutputDebugString(L"[IDispatch::MyRelease] goto g_hookmanager -> Find");
#endif
	if((pInfo = (CIDispatchHookInfo *)g_HookManager->Find(This)) == NULL)
		return 0;

	// 2. call the original method
	result = pInfo->Release(This);

	// 3. if the original method returns 0
	if(result == 0)
	{
#ifdef _DEBUG
		OutputDebugString(L"[IDispatch::MyRelease] object count decreased to 0");
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
	OutputDebugString(L"[IClassFactory::MyFRelease] goto g_hookmanager -> Find");
#endif
	if((pInfo = (CIClassFactoryHookInfo *)g_HookManager->Find(This)) == NULL)
		return 0;
	result = pInfo->Release(This);
#ifdef _DEBUG
	LPOLESTR clsid;
	OLECHAR debugstr[MAX_PATH];
	//REFCLSID rclsid = pInfo->GetCLSID(This);
	StringFromCLSID(pInfo->GetCLSID(This), &clsid);
	swprintf_s(debugstr, L"[IClassFactory::MyFRelease] clsid: %s, result is %d", clsid, result);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
#endif
	if(result < 0)
	{
#ifdef _DEBUG
		OutputDebugString(L"[IClassFactory::MyFRelease] object count decreased BELOW to 0");
#endif
	}
	else if(result == 0){
#ifdef _DEBUG
		OutputDebugString(L"[IClassFactory::MyFRelease] object count decreased to 0");
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
	OLECHAR debugstr[MAX_PATH];
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
bool CheckTaintSource(WORD &wFlags, DISPPARAMS *p){
	UINT parameterCount = p->cArgs;
	bool result = true;
	if((wFlags == DISPATCH_METHOD || wFlags == DISPATCH_PROPERTYPUT) && parameterCount > 0){
		for(UINT i = 0; i < parameterCount; i++){
			if(p ->rgvarg[i].vt == VT_EMPTY){
				result = false;
				break;
			}
		}
		return result;
	}
	return false;
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
	std::ofstream axmockOutput;
	LPOLESTR clsid;
	OLECHAR debugstr[MAX_PATH];
	BSTR method;
	//BSTR destBSTR;
	std::ifstream fuzzInput;

#ifdef _DEBUG
	OutputDebugString(L"[IDispatch::Invoke] Start");
#endif

	// 1. get the corresponding HookInfo using This
	if((pInfo = (CIDispatchHookInfo *)g_HookManager->Find(This)) == NULL)
		return E_FAIL;

	StringFromCLSID(pInfo->GetCLSID(This), &clsid);

#ifdef _DEBUG
	swprintf_s(debugstr, MAX_PATH, L"[IDispatch::Invoke] clsid: %s, Flags: %08x, Address: %08x", clsid, wFlags, This);
	OutputDebugString(debugstr);	
#endif

	// TODO: CHECK if we should put invokeCount++ here	
	invokeCount++;
	method = pInfo->FindDispID(This, dispIdMember);	
	
	fuzzInput.open(FUZZINPUT, std::ios::binary);
	if(fuzzInput.is_open()){
#ifdef _DEBUG
		OutputDebugString(L"[IDispatch::Invoke] Start Fuzzing");
#endif
		int ifContinue, functionNumber, paramNumber, paramLength, maxLength;
		char char_Method[20], *char_paramVal, *destChar;
		string paramVal;
		
		fuzzInput >> ifContinue;
		if(ifContinue){
			memset(char_Method, 0, sizeof(char_Method));
			fuzzInput >> functionNumber >> char_Method >> paramNumber >> paramLength >> maxLength;
			char_paramVal = new char[paramLength + 1];
			memset(char_paramVal, 0, sizeof(char) * (paramLength + 1));
			
			fuzzInput >> paramVal;
			decode(paramVal, char_paramVal);
			swprintf_s(debugstr, MAX_PATH, L"[IDispatch::Invoke] functionNumber is %d, invokeCount is %d, paramNumber is %d, maxlength is %d", functionNumber, invokeCount, paramNumber, maxLength);
			OutputDebugString(debugstr);
			
			//consider as same invocation, so change the param string
			if(invokeCount == functionNumber && IsEqualBSTR_CHAR(method, char_Method) 
				&& IsEqualBSTR_CHAR(pDispParams->rgvarg[paramNumber].bstrVal, char_paramVal)){
				
				destChar = new char[maxLength +1];
				memset(destChar, 0, sizeof(char) * (maxLength + 1));
				
				for(int i = 0; i < maxLength; i++)
					destChar[i] = char_paramVal[i];
				//pDispParams->rgvarg[paramNumber].bstrVal = ::SysAllocString(L"aaaa");
				pDispParams->rgvarg[paramNumber].bstrVal = ConvertLPSTRToBSTR(destChar);
				//memset(pDispParams->rgvarg[paramNumber].bstrVal, 0, sizeof(char));
				swprintf_s(debugstr, MAX_PATH, L"[IDispatch::Invoke] address of bstrVal is %0x", &pDispParams->rgvarg[paramNumber].bstrVal);
				OutputDebugString(debugstr);
/*
#ifdef _DEBUG
				OLECHAR tdebugstr[700];
				swprintf_s(tdebugstr, 700, L"[IDispatch::Invoke] destBSTR is %s", destBSTR);
				OutputDebugString(tdebugstr);
#endif
*/
//				::SysFreeString(pDispParams->rgvarg[paramNumber].bstrVal);
//				pDispParams->rgvarg[paramNumber].bstrVal = SysAllocString(destBSTR);
//				::SysFreeString(destBSTR);
/*
#ifdef _DEBUG				
				swprintf_s(tdebugstr, 700, L"[IDispatch::Invoke]The modified string is %s", pDispParams->rgvarg[paramNumber].bstrVal);
				OutputDebugString(tdebugstr);
#endif
*/
			}
			delete char_paramVal;
			//delete destChar;
		}
		fuzzInput.close();
	}//endif fuzzInput is open
	else
		OutputDebugString(L"[IDispatch::Invoke] not open fuzz");


	
	// 2.1 If IDispatch is recorder, then we believe that the function is Judge function
	if(This == recIDispatch){
		OutputDebugString(L"[IDispatch::Invoke] Arriving the recorder");
		return TRUE;
	}
	// 2.2 True calling, which means the invocation is from available method or the emulated method 
	else{
		ofstream confirmOutput;
		confirmOutput.open(CONFIRMOUTPUT, ios::out);
		if(CheckTaintSource(wFlags, pDispParams)){
			int parameterCount = pDispParams->cArgs;
			confirmOutput << 1 << endl << parameterCount << endl;
			for(int i = 0; i < parameterCount; i++)
				OutputParameter2(pDispParams->rgvarg[i], confirmOutput);
		}
		else
			confirmOutput << 0 << endl;
		confirmOutput.close();
		// 2.2.2 axmock Record the invocation information
		
		OutputDebugString(L"[IDispatch::Invoke] AxmockOutput");
		
		axmockOutput.open(AXMOCKOUTPUT, std::ios::app, std::ios::binary);
		axmockOutput << invokeCount << std::endl;
		axmockOutput << ConvertBSTRToLPSTR(::SysAllocString(clsid)) << std::endl;
		axmockOutput << pInfo -> Invoke << std::endl;
		axmockOutput << wFlags << std::endl;
		if(wFlags == DISPATCH_METHOD){
			axmockOutput << ConvertBSTRToLPSTR(method) << std::endl;
			int parameterCount = pDispParams->cArgs;
			axmockOutput << parameterCount << std::endl;
			for(int i = 0; i < parameterCount; i++)
				OutputParameter2(pDispParams->rgvarg[i], axmockOutput);
		}
		else if (wFlags == DISPATCH_PROPERTYGET){
			OutputParameter2(*pVarResult, axmockOutput);
		}
		axmockOutput << std::endl;
		axmockOutput.flush();
		axmockOutput.close();
		if(method != NULL){
			std::ofstream outputFile, outputFile_PIN;
			outputFile.open("C:\\4Reading.log");
			outputFile_PIN.open("C:\\pinInput.log");
			
			if(!outputFile.is_open())
				OutputDebugString(L"File write error!");
			swprintf_s(debugstr, MAX_PATH, L"[IDispatch::Invoke]The calling method is : %s", method);
			OutputDebugString(debugstr);
			outputFile << "Original Function Address: " << (pInfo->Invoke) << std::endl;
//			outputFile << "Original Function Address: " << pInfo->m_vtbl << std::endl;
			outputFile << "Method Name: " << ConvertBSTRToLPSTR(method) << std::endl;
			swprintf_s(debugstr, MAX_PATH, L"%d", pDispParams->cArgs);
			outputFile << "Parameter Count: " << pDispParams->cArgs << std::endl;
			OutputDebugString(debugstr);
			for(unsigned int i = 0; i < pDispParams->cArgs; i++){
				swprintf_s(debugstr, MAX_PATH, L"%d", pDispParams->rgvarg[i].vt);
				OutParameter(pDispParams->rgvarg[i], outputFile);
				OutputDebugString(debugstr);
			}

			if(!outputFile_PIN.is_open())
				OutputDebugString(L"File write error!");
			swprintf_s(debugstr, MAX_PATH, L"The calling method is : %s", method);
			OutputDebugString(debugstr);
			
			outputFile_PIN << (pInfo->Invoke) << std::endl;
			outputFile_PIN << (pDispParams->rgvarg[0].bstrVal) << std::endl;
			time_t rawtime;
			struct tm *timeinfo;
			time(&rawtime);
			timeinfo = localtime(&rawtime);
			outputFile_PIN << "1" << std::endl;
			outputFile_PIN << asctime(timeinfo) << std::endl;
			outputFile_PIN.flush();
			outputFile_PIN.close();
			outputFile.close();
			
		}//endif
		//3. check if fuzz introducted
				
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
		CoTaskMemFree(clsid);
		::SysFreeString(method);
		//CoTaskMemFree(destBSTR);
		return result;
	}
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
	HRESULT result;
	OLECHAR Methodstr[200];
	BSTR bstrText;
	//CComBSTR a;
#ifdef _DEBUG
	OLECHAR debugstr[MAX_PATH];
	LPOLESTR clsid;
#endif

#ifdef _DEBUG
	swprintf_s(debugstr, 200, L"[IDispatchEx::MyGetDispID] GetDispID This interface: %08x, grfdex %0x", This, grfdex);
	OutputDebugString(debugstr);
#endif
	//1. If the call is from emulator, do not transform the name
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
	//1+. If the call is from recorder:
	//  (1) Record the method name
	//  (2) return the judge method
	else if (This == recIDispatchEx){
		if((pInfo = (CIDispatchExHookInfo *)g_HookManager->Find(This)) == NULL)
			return E_FAIL;
		swprintf_s(debugstr, 200, L"[IDispatchEx::MyGetDispID] GetDispID for recorder, grfdex is %d", grfdex);
		OutputDebugString(debugstr);
		bstrText = ::SysAllocString(L"Judge");
		swprintf_s(Methodstr, 200, L"%s", bstrText);
		bstrText = ::SysAllocString(Methodstr);
		OutputDebugString(Methodstr);
		result = pInfo ->GetDispID(This, bstrText, grfdex, pid);
		if(FAILED(result)){
			swprintf_s(debugstr, 200, L"[IDispatchEx::MyGetDispID] failed Recorder call Judge function, result %08x", result);
			OutputDebugString(debugstr);
		}
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
	std::ofstream axmockOutput;
	CIDispatchExHookInfo *pInfo;
	//HRESULT result;
#ifdef _DEBUG
	LPOLESTR clsid;
	OLECHAR debugstr[MAX_PATH];
#endif

	axmockOutput.open(AXMOCKOUTPUT, std::ios::app, std::ios::binary);


#ifdef _DEBUG
	OutputDebugString(L"[IDispatchEx::InvokeEx]Start");
#endif

	// 1. get the corresponding HookInfo using This
	if((pInfo = (CIDispatchExHookInfo *)g_HookManager->Find(This)) == NULL)
		return E_FAIL;
	
	invokeCount++;

#ifdef _DEBUG
	StringFromCLSID(pInfo->GetCLSID(This), &clsid);
	swprintf_s(debugstr, 200, L"[IDispatchEx::InvokeEx] clsid: %s, ID: %d, Flags: %08x", clsid, id, wFlags);
	OutputDebugString(debugstr);
	CoTaskMemFree(clsid);
	swprintf_s(debugstr, 200, L"[IDispatchEx::InvokeEx] This %08x", This);
	OutputDebugString(debugstr);
	swprintf_s(debugstr, 200, L"[IDispatchEx::InvokeEx] recIDispatchEx %08x", recIDispatchEx);
	OutputDebugString(debugstr);
#endif

	// 2. if the invoker is recorder, we record all the parameters, and return true
	if(This == recIDispatchEx){
		axmockOutput << invokeCount << std::endl;
		OutputDebugString(L"[IDispatchEx::InvokeEx] Tend to find parameter");
		int ParameterCount;
		ParameterCount = (int)(pdp ->cArgs);
		axmockOutput << "Parameter Count" << ParameterCount << std::endl;
		swprintf_s(debugstr, 200, L"[IDispahtchEx::InvokeEx] Parameter Count is %d", ParameterCount);
		OutputDebugString(debugstr);
		
		for(int i = 0; i < ParameterCount; i++){
			swprintf_s(debugstr, MAX_PATH, L"%d", pdp->rgvarg[i].vt);
			OutputDebugString(debugstr);
			OutParameter(pdp->rgvarg[i], axmockOutput);
		}
		return TRUE;
	}
	else{
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
}
