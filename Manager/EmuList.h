#pragma once

#include <ole2.h>
#include <list>

using std::list;

namespace COMSniffer {

#define BSTR_COMPARE(BSTR1,BSTR2) ((SysStringLen(BSTR1) == SysStringLen(BSTR2)) &&  (wcscmp(BSTR1,BSTR2) == 0))
	
	class CEmuList
	{
	public:
		CEmuList();
		CEmuList(WCHAR *emulist);
		~CEmuList();

		BOOLEAN AddToEmuList(LPCOLESTR hookname, LPOLESTR clsid_str, LPCOLESTR progid);
		BOOLEAN AddToEmuList(LPCOLESTR hookname, REFCLSID rclsid, LPCOLESTR progid);
		BOOLEAN IsInEmuList(LPCOLESTR progid, LPCLSID pclsid);
		BOOLEAN IsInEmuList(REFCLSID rclsid);
		BOOLEAN GetHookName(REFCLSID pclsid, BSTR &hookname);
	private:
		class EmuListItem{
		public:
			EmuListItem(BSTR hookname, REFCLSID rclsid, BSTR progid) {m_hookname = hookname, m_clsid = rclsid, m_progid = progid;};
			~EmuListItem() {SysFreeString(m_progid);};
			
			BSTR m_hookname;
			CLSID m_clsid;
			BSTR m_progid;
		};

		list<EmuListItem *> m_list;
		CRITICAL_SECTION m_cs;
	};
};