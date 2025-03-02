#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include "ntapi.h"

typedef struct _PE_HEADER {
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeader;
	PIMAGE_SECTION_HEADER sectionHeader;

	_PE_HEADER(BYTE* base) {
		dosHeader = (PIMAGE_DOS_HEADER)base;
		ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);
		sectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)ntHeader + sizeof(IMAGE_NT_HEADERS));
	}
} PE_HEADER;


BYTE* DecompressBuffer() {
	BYTE* stubBase = (BYTE*)GetModuleHandleA(NULL);
	PE_HEADER stubHeader(stubBase);
	PIMAGE_SECTION_HEADER packedSection = &stubHeader.sectionHeader[stubHeader.ntHeader->FileHeader.NumberOfSections - 1];
	
	DWORD compressBufferSize = packedSection->SizeOfRawData;
	BYTE* compressBuffer = stubBase + packedSection->VirtualAddress;
	
	DWORD uncompressBufferSize = compressBufferSize * 2;
	BYTE* uncompressBuffer = (BYTE*)VirtualAlloc(NULL, uncompressBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!uncompressBuffer) {
		printf("Cannot allocated for uncompressBuffer!");
		exit(1);
	}

	DWORD finalSize;
	NTSTATUS status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, (PUCHAR)uncompressBuffer,
		uncompressBufferSize, (PUCHAR)compressBuffer, compressBufferSize, &finalSize);
	if (status != 0) {
		printf("RtlDecompressBuffer fail with status code %i", status);
		exit(1);
	}

	return uncompressBuffer;
}


BYTE* LoadNewImage() {
	BYTE* rawAddress = DecompressBuffer();
	PE_HEADER newImageHeader(rawAddress);

	BYTE* newImageBase = (BYTE*)VirtualAlloc(NULL, newImageHeader.ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (newImageBase == NULL) {
		printf("Cannot allocate memory for newImageBase!");
		exit(1);
	}

	memcpy(newImageBase, rawAddress, newImageHeader.ntHeader->OptionalHeader.SizeOfHeaders);
	for (int i = 0; i < newImageHeader.ntHeader->FileHeader.NumberOfSections; i++) {
		BYTE* src = (BYTE*)rawAddress + newImageHeader.sectionHeader[i].PointerToRawData;
		BYTE* dst = newImageBase + newImageHeader.sectionHeader[i].VirtualAddress;
		memcpy(dst, src, newImageHeader.sectionHeader[i].SizeOfRawData);
	}

	return newImageBase;
}


void ResolveIAT(BYTE* newImageBase) {
	PE_HEADER newPeHeader(newImageBase);

	DWORD importRVA = newPeHeader.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!importRVA) {
		printf("Cannot resolve IAT!");
		exit(1);
	}

	PIMAGE_IMPORT_DESCRIPTOR importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(newImageBase + importRVA);
	for (int i = 0; importDirectory[i].Name != 0; i++) {
		HMODULE hModule = LoadLibraryA((char*)(newImageBase + importDirectory[i].Name));
		DWORD* IAT = (DWORD*)(newImageBase + importDirectory[i].FirstThunk);

		for (int j = 0; IAT[j] != 0; j++) {
			if (IAT[j] & IMAGE_ORDINAL_FLAG32) {
				DWORD ordinal = IMAGE_ORDINAL32(IAT[j]);
				IAT[j] = (DWORD)GetProcAddress(hModule, (LPCSTR)ordinal);
			}
			else {
				PIMAGE_IMPORT_BY_NAME nameTable = (PIMAGE_IMPORT_BY_NAME)(newImageBase + IAT[j]);
				IAT[j] = (DWORD)GetProcAddress(hModule, nameTable->Name);
			}
		}
	}
}


void FixRelocation(BYTE* newImageBase) {
	PE_HEADER newPeHeader(newImageBase);

	DWORD relocRVA = newPeHeader.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD relocSize = newPeHeader.ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if (relocSize == 0) {
		printf("Cannot fix relocation!");
		exit(1);
	}

	PIMAGE_BASE_RELOCATION relocDirectory = (PIMAGE_BASE_RELOCATION)(newImageBase + relocRVA);
	DWORD delta = (DWORD)newImageBase - newPeHeader.ntHeader->OptionalHeader.ImageBase;
	while (relocDirectory->SizeOfBlock != 0) {
		WORD* relocData = (WORD*)((BYTE*)relocDirectory + sizeof(IMAGE_BASE_RELOCATION));
		for (int i = 0; relocData[i] != 0; i++) {
			if ((relocData[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
				DWORD* patch = (DWORD*)(newImageBase + relocDirectory->VirtualAddress + (relocData[i] & 0xFFF));
				*patch += delta;
			}
		}
		relocDirectory = (PIMAGE_BASE_RELOCATION)((BYTE*)relocDirectory + relocDirectory->SizeOfBlock);
	}
}


void UpdatePEB(BYTE* newImageBase) {
	BYTE* peb = (BYTE*)__readfsdword(0x30);
	DWORD* pebImageBase = (DWORD*)(peb + 0x8);
	*pebImageBase = (DWORD)newImageBase;
}


int main() {
	RtlDecompressBuffer = (pRtlDecompressBuffer)ResolveAPI("ntdll.dll", "RtlDecompressBuffer");

	BYTE* newImageBase = LoadNewImage();

	ResolveIAT(newImageBase);

	FixRelocation(newImageBase);
	
	UpdatePEB(newImageBase);
	
	PE_HEADER newPeHeader(newImageBase);
	typedef void (*EntryPoint)();
	EntryPoint OEP = (EntryPoint)(newImageBase + newPeHeader.ntHeader->OptionalHeader.AddressOfEntryPoint);
	OEP();

	return 0;
}