#include "header.h"

BYTE* ReadFile(char* filePath, DWORD& bufferSize) {
	HANDLE hFile = CreateFileA(filePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open file %s", filePath);
		exit(1);
	}

	DWORD fileSize = GetFileSize(hFile, NULL);
	BYTE* base = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (base == NULL) {
		printf("Cannot allocate memory!");
		exit(1);
	}

	DWORD bytesRead;
	ReadFile(hFile, base, fileSize, &bytesRead, NULL);
	if (bytesRead != fileSize) {
		printf("Failed to read complete file %s\n", filePath);
		exit(1);
	}

	CloseHandle(hFile);
	if (!IsValidPE(base))
		exit(1);

	bufferSize = fileSize;
	return base;
}


void WriteFile(const char* inputFileName, BYTE* buffer, DWORD bufferSize) {
	string inputFile = inputFileName;
	string outputFile = inputFile.substr(0, inputFile.find_last_of('.')) + "_packed.exe";

	HANDLE hFile = CreateFileA(outputFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open file %s", outputFile.c_str());
		exit(1);
	}

	DWORD byteWritten = 0;
	WriteFile(hFile, buffer, bufferSize, &byteWritten, NULL);
	CloseHandle(hFile);

	if (byteWritten != bufferSize) {
		printf("Fail to write to file %s", outputFile.c_str());
		exit(1);
	}
	else {
		printf("Packed file save as: %s", outputFile.c_str());
	}
}


void ProcessNewPeHeader(BYTE* newPeBase, BYTE* stubBase, BYTE* exeBase, DWORD exeSize) {
	PE_HEADER stubHeader(stubBase);
	PE_HEADER newPeHeader(newPeBase);
	PE_HEADER exeHeader(exeBase);

	PWORD pNumberOfSection = &newPeHeader.ntHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER packedSection = &newPeHeader.sectionHeader[*pNumberOfSection];
	PIMAGE_SECTION_HEADER lastSection = &newPeHeader.sectionHeader[*pNumberOfSection - 1];

	strcpy_s((char*)packedSection->Name, 8, ".packed");
	packedSection->VirtualAddress = CalculateAlignAddress(lastSection->VirtualAddress, lastSection->Misc.VirtualSize, 0x1000);
	packedSection->Misc.VirtualSize = exeSize + 0x100;
	packedSection->PointerToRawData = CalculateAlignAddress(lastSection->PointerToRawData, lastSection->SizeOfRawData, 0x200);
	packedSection->SizeOfRawData = exeSize;
	packedSection->Characteristics = 0xE0000040;

	*pNumberOfSection += 1;
	DWORD newPeImageSize = stubHeader.ntHeader->OptionalHeader.SizeOfImage + exeHeader.ntHeader->OptionalHeader.SizeOfImage;
	newPeHeader.ntHeader->OptionalHeader.SizeOfImage = newPeImageSize;
	newPeHeader.ntHeader->OptionalHeader.SizeOfHeaders = 0x1000;
}


PVOID CompressBuffer(PVOID uncompressBuffer, DWORD uncompressBufferSize, DWORD& finalSize) {
	DWORD workSpaceSize;
	DWORD fragmentWorkSpaceSize;
	NTSTATUS workSpaceStatus = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1, &workSpaceSize, &fragmentWorkSpaceSize);
	if (workSpaceStatus != 0) {
		printf("RtlGetCompressionWorkSpaceSize fail with status code %i", workSpaceStatus);
		exit(1);
	}

	PVOID workSpace = VirtualAlloc(NULL, workSpaceSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!workSpace) {
		printf("Cannot allocated for workSpace");
		exit(1);
	}

	DWORD compressBufferSize = uncompressBufferSize + (uncompressBufferSize / 16) + 64;
	PVOID compressBuffer = VirtualAlloc(NULL, compressBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!compressBuffer) {
		printf("Cannot allocated for compressBuffer");
		exit(1);
	}

	NTSTATUS compressStatus = RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1, (PUCHAR)uncompressBuffer, uncompressBufferSize,
		(PUCHAR)compressBuffer, compressBufferSize, 4096, &finalSize, workSpace);
	if (compressStatus != 0) {
		printf("RtlCompressBuffer fail with status code %i", compressStatus);
		exit(1);
	}

	VirtualFree(workSpace, 0, MEM_RELEASE);
	return compressBuffer;
}


int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Usage: %s <file_to_pack>", argv[0]);
		return 1;
	}

	RtlCompressBuffer = (pRtlCompressBuffer)ResolveAPI("ntdll.dll", "RtlCompressBuffer");
	RtlGetCompressionWorkSpaceSize = (pRtlGetCompressionWorkSpaceSize)ResolveAPI("ntdll.dll", "RtlGetCompressionWorkSpaceSize");

	DWORD stubSize = sizeof(stub);
	BYTE* stubBase = (BYTE*)&stub;
	DWORD exeSize = 0;
	BYTE* exeBase = ReadFile(argv[1], exeSize);

	DWORD finalSize;
	PVOID compressBuffer = CompressBuffer(exeBase, exeSize, finalSize);

	BYTE* newPeBase = (BYTE*)VirtualAlloc(NULL, stubSize + finalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(newPeBase, stubBase, stubSize);
	memcpy(newPeBase + stubSize, compressBuffer, finalSize);

	ProcessNewPeHeader(newPeBase, stubBase, exeBase, finalSize);
	WriteFile(argv[1], newPeBase, stubSize + finalSize);

	VirtualFree(stubBase, 0, MEM_RELEASE);
	VirtualFree(exeBase, 0, MEM_RELEASE);
	VirtualFree(newPeBase, 0, MEM_RELEASE);
	VirtualFree(compressBuffer, 0, MEM_RELEASE);
	return 0;
}