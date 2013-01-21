#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include "detours.h"
#include "sigscan.h"
#include <stdio.h>
#include "GarrysMod/Lua/Interface.h"

#define SHOULDREPORT_SIG "\x55\x8B\xEC\x83\xEC\x24\x53\x8B\x1D"
#define SHOULDREPORT_MASK "xxxxxxxxx"

typedef bool (*tShouldReport)(const char**);
tShouldReport origShouldReport = NULL;

using namespace GarrysMod::Lua;

bool hkShouldReport(const char** err)
{
	printf("[gmsv_noreport] Not sending error\n");
	return false;
}

GMOD_MODULE_OPEN()
{
	CSigScan sigscan("server.dll");
	if(!sigscan.IsReady())
	{
		LUA->ThrowError("[gmsv_noreport] Failed to find base of server.dll");
		return 0;
	}

	// Sigscan for ShouldReportErrorToFacepunch
	void* addrShouldReport = sigscan.Scan((unsigned char*)SHOULDREPORT_SIG, SHOULDREPORT_MASK);
	if(addrShouldReport == NULL)
	{
		LUA->ThrowError("[gmsv_noreport] Failed to sigscan for ShouldReportErrorToFacepunch");	
		return 0;
	}

	origShouldReport = (tShouldReport)addrShouldReport;
	
	// Detour the function to call hkShouldReport instead
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)origShouldReport, hkShouldReport);
	DetourTransactionCommit();

	return 0;
}

GMOD_MODULE_CLOSE()
{
	if(origShouldReport != NULL)
	{
		// Detach the detour
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)origShouldReport, hkShouldReport);
		DetourTransactionCommit();
	}

	return 0;
}