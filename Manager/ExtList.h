#pragma once

#include <ole2.h>
#include <list>

using std::list;

namespace COMSniffer {

#define BSTR_COMPARE(BSTR1,BSTR2) ((SysStringLen(BSTR1) == SysStringLen(BSTR2)) &&  (wcscmp(BSTR1,BSTR2) == 0))
	
	class CExtList
	{
	public:
		CExtList();
		CExtList(WCHAR *emulist);
		~CExtList();

		BOOLEAN AddToExtList(LPCOLESTR hookname, LPOLESTR clsid_str, LPCOLESTR progid);
		BOOLEAN AddToExtList(LPCOLESTR hookname, REFCLSID rclsid, LPCOLESTR progid);
		BOOLEAN IsInExtList(LPCOLESTR progid, LPCLSID pclsid);
		BOOLEAN IsInExtList(REFCLSID rclsid);
		BOOLEAN GetHookName(REFCLSID pclsid, BSTR &hookname);
	private:
		class ExtListItem{
		public:
			ExtListItem(BSTR hookname, REFCLSID rclsid, BSTR progid) {m_hookname = hookname, m_clsid = rclsid, m_progid = progid;};
			~ExtListItem() {SysFreeString(m_progid);};
			
			BSTR m_hookname;
			CLSID m_clsid;
			BSTR m_progid;
		};

		list<ExtListItem *> m_list;
		CRITICAL_SECTION m_cs;
	};
};