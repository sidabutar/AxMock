#pragma once

#include <ole2.h>
#include <map>
#include "HookInfo.h"

using std::map;
/*struct HookInfoKey{
	REFCLSID clsid;
	PVOID vtbl;
	int flag;
};
*/
namespace COMSniffer
{
	class CHookManager
	{
	public:
		CHookManager();
		~CHookManager();

		// hook an object's IDispatch interface
		BOOLEAN AddRef(IDispatch *object, REFCLSID clsid);
		BOOLEAN AddRef(IDispatchEx *object, REFCLSID clsid);
		// hook an object's IClassFactory interface
		BOOLEAN AddRef(IClassFactory *object, REFCLSID clsid);

		// find an object's corresponding HookInfo
		PVOID Find(const PVOID object);

		// unhook an object
		VOID Release(CBaseHookInfo *HookInfo, const PVOID object, const PVOID vtbl);

	private:
		// PVOID = vtable address
		map<PVOID, CBaseHookInfo *> m_hinfo;

		CRITICAL_SECTION m_cs;
	};
};