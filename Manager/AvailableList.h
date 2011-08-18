#pragma once

#include <ole2.h>
#include <list>

using std::list;

namespace COMSniffer {

#define BSTR_COMPARE(BSTR1,BSTR2) ((SysStringLen(BSTR1) == SysStringLen(BSTR2)) &&  (wcscmp(BSTR1,BSTR2) == 0))
	
	class CAvailableList
	{
	public:
		CAvailableList();
		CAvailableList(WCHAR *blacklist);
		~CAvailableList();

		BOOLEAN AddToAvailableList(REFCLSID rclsid, LPCOLESTR progid);
		BOOLEAN AddToAvailableList(LPOLESTR clsid_str, LPCOLESTR progid);
		VOID RemoveFromAvailableList(REFCLSID rclsid);
		VOID RemoveFromAvailableList(LPCOLESTR progid);
		BOOLEAN IsInAvailableList(REFCLSID rclsid);
		BOOLEAN IsInAvailableList(LPCOLESTR progid, LPCLSID pclsid);
		BOOLEAN ProgIDFromCLSID(REFCLSID rclsid, LPOLESTR *progid);

	private:
		class AvailableListItem
		{
		public:
			AvailableListItem(REFCLSID rclsid, BSTR progid) {m_clsid = rclsid, m_progid = progid;};
			~AvailableListItem() {SysFreeString(m_progid);};

			CLSID m_clsid;
			BSTR m_progid;
		};

		list<AvailableListItem *> m_list;
		CRITICAL_SECTION m_cs;
	};

};