#pragma once
#include <Windows.h>

PVOID ResolveAPI(const char* dllName, const char* apiName) {
	HMODULE hLib = LoadLibraryA(dllName);
	if (!hLib) {
		printf("Cannot load %s", dllName);
		exit(1);
	}

	PVOID apiAddress = GetProcAddress(hLib, apiName);
	if (!apiAddress) {
		printf("Cannot Resolve API %s", apiName);
		exit(1);
	}
	return apiAddress;
}


typedef NTSTATUS(WINAPI* pRtlCompressBuffer)(
	USHORT CompressionFormatAndEngine,
	PUCHAR UncompressedBuffer,
	ULONG  UncompressedBufferSize,
	PUCHAR CompressedBuffer,
	ULONG  CompressedBufferSize,
	ULONG  UncompressedChunkSize,
	PULONG FinalCompressedSize,
	PVOID  WorkSpace
	);


typedef NTSTATUS(WINAPI* pRtlGetCompressionWorkSpaceSize)(
	USHORT CompressionFormatAndEngine,
	PULONG CompressBufferWorkSpaceSize,
	PULONG CompressFragmentWorkSpaceSize
	);


typedef NTSTATUS(WINAPI* pRtlDecompressBuffer)(
	USHORT CompressionFormat,
	PUCHAR UncompressedBuffer,
	ULONG  UncompressedBufferSize,
	PUCHAR CompressedBuffer,
	ULONG  CompressedBufferSize,
	PULONG FinalUncompressedSize
	);

pRtlCompressBuffer RtlCompressBuffer;
pRtlDecompressBuffer RtlDecompressBuffer;
pRtlGetCompressionWorkSpaceSize RtlGetCompressionWorkSpaceSize;

