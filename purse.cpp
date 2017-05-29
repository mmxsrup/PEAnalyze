#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <string>

//#define DEBUG

struct IMAGE_DOS_HEADER {
	uint16_t e_magic;    // Magic Number (0x4d5a)
	uint16_t e_cblp;     // Bytes on last page of file
	uint16_t e_cp;       // Pages in file
	uint16_t e_crlc;     // Relocations
	uint16_t e_cparhdr;  // Size of header in paragraphs
	uint16_t e_minalloc; // Minimum extra paragraphs needed
	uint16_t e_maxalloc; // Maximum extra paragraohs needed
	uint16_t e_ss;       // Initial SS value
	uint16_t e_sp;       // Initial SP value
	uint16_t e_csum;     // Checksum
	uint16_t e_ip;       // Initial IP value
	uint16_t e_cs;       // Initial CS value
	uint16_t e_lfarlc;   // File address of relocation table;
	uint16_t e_ovno;     // Overlay number
	uint16_t e_res[4];   // Reserved words
	uint16_t e_oemid;    // OEM identifier
	uint16_t e_oeminfo;  // OEM information
	uint16_t e_res2[10]; // Reserved words
	uint32_t e_lfnew;    // File address of new exe header(NT header) 
};

struct IMAGE_DATA_DIRECTORY{
	uint32_t VirtualAddress; //ロードされたイメージからの先頭アドレス
	uint32_t Size;
};
struct IMAGE_FILE_HEADER{
	uint16_t Machine;              // x86(0x014c) x64(0x8664)
	uint16_t NumberOfSections;     // セクションの数
	uint32_t TimeDateStamp;        // Unix time
	uint32_t PointerToSymbolTable; // 0x0000 使わない
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptopmalHeader; // IMAGE_OPTIONAL_HEADERのサイズ
	uint16_t Characteristics;
};
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
struct IMAGE_OPTIONAL_HEADER{
	uint16_t Magic; // PE32(0x010b) PE64(0x020b)
	uint8_t  MajorLinkerVersion;
	uint8_t  MinorLinlerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint; // relative virtual address
	uint32_t BaseOfCode;
	uint32_t BaseOfData;
	uint32_t ImageBase; // ロードアドレス
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint32_t SizeOfStackReserve;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes; //0x10(IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_NT_HEADERS {
	uint32_t Signature; // Magic Number (0x50450000)
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
};

// IMAGE_SECTION_HEADER の数はIMAGE_FILE_HEADER::NumberOfSectionsで定義されている
#define IMAGE_SIZEOF_SHORT_NAME    8
struct IMAGE_SECTION_HEADER {
	char Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		uint32_t PhysicalAddress;
		uint32_t VirtualSize;
	} Misc;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData; //このセクションのファイル中でのサイズ
	uint32_t PointerToRawData; //このセクションのファイル中での位置
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Characteristics; // (0x00000040)セクションに初期化されたデータが含まれている
};

struct IMAGE_RESOURCE_DIRECTORY {
	uint32_t Characteristics;
	uint32_t TimeDateStamp;
	uint16_t MajorVersion;
	uint16_t MinorVersion;
	uint16_t NumberOfNamedEntries; // IMAGE_RESOURCE_DIRECTORY_ENTRY構造体の数
	uint16_t NumberOfIdEntries; // IMAGE_RESOURCE_DIRECTORY_ENTRY構造体の数
//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
};
struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
	union {
		struct {
			uint32_t NameOffset:31;
			uint32_t NameIsString:1;
		};
		uint32_t Name;
		uint16_t Id;
	};
	union {
		uint32_t OffsetToData;
		struct {
			uint32_t OffsetToDirectory:31;
			uint32_t DataIsDirectory:1;
		};
	};
};
struct IMAGE_RESOURCE_DATA_ENTRY {
	uint32_t OffsetToData;
	uint32_t Size;
	uint32_t CodePage;
	uint32_t Reserved;
};
struct IMAGE_COR20_HEADER {
	uint32_t cb;
	uint16_t MajorRuntimeVersion;
	uint16_t MinorRuntimeVersion;
	IMAGE_DATA_DIRECTORY MetaData;
	uint32_t Flags;
	union {
		uint32_t EntryPointToken;
		uint32_t EntryPointRVA;
	};
	IMAGE_DATA_DIRECTORY Resources;
	IMAGE_DATA_DIRECTORY StrongNameSignature;
	IMAGE_DATA_DIRECTORY CodeManagerTable;
	IMAGE_DATA_DIRECTORY VTableFixups;
	IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
	IMAGE_DATA_DIRECTORY ManagedNativeHeader;
};

struct IMAGE_METADATA_ROOT {
	uint32_t Signature; /*0x424a5342 */
	uint16_t MajorVersion;
	uint16_t MinorVersion;
	uint32_t Reserved;
	uint32_t Length;
	// uiint8_t Version[Length];
	// Alignment (4の倍数)
	// uint16_t Flags;
	// uint16_t Streams;
};

struct IMAGE_STREAM_HEADER {
	uint32_t Offset;
	uint32_t Size;
	char Name[32]; // 実際のサイズはSize + alignment
};


void Print_IMAGE_DOS_HEADER(IMAGE_DOS_HEADER *data) {
	printf("-----IMAGE_DOS_HEADER-----\n");
	printf("e_magic: %x\n", data->e_magic);
	printf("e_lfnew: %x\n", data->e_lfnew);
	printf("\n");
}
void Print_IMAGE_NT_HEADERS(IMAGE_NT_HEADERS *data) {
	printf("-----IMAGE_NT_HEADERS-----\n");
	static const char* list[] = {
		"EXPORT", "IMPORT", "RESORCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE",
		"GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "Nothing"
	};
	printf("Signature: %x\n", data->Signature);
	printf("Machine : %x\n", data->FileHeader.Machine);
	printf("NumberOfSections: %x\n", data->FileHeader.NumberOfSections);
	printf("Magic : %x\n", data->OptionalHeader.Magic);
	printf("ImageBase : %x\n", data->OptionalHeader.ImageBase);
	printf("SizeOfStackReserve: %x\n", data->OptionalHeader.SizeOfStackReserve);
	printf("SizeOfStackCommit: %x\n", data->OptionalHeader.SizeOfStackCommit);
	printf("LoaderFlags: %x\n", data->OptionalHeader.LoaderFlags);
	printf("NumberOfRvaAndSizes : %x\n", data->OptionalHeader.NumberOfRvaAndSizes);
	printf("---IMAGE_DATA_DIRECTORY---\n");
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i){
		printf("%16s : VirtualAddress : %8x size: %8x\n", list[i],
			data->OptionalHeader.DataDirectory[i].VirtualAddress,
			data->OptionalHeader.DataDirectory[i].Size);
	}
	printf("\n");
}
void Print_IMAGE_SECTION_HEADER(IMAGE_SECTION_HEADER *data) {
	printf("----- %s Section -----\n", data->Name);
	printf("VirtualAddress: %x\n", data->VirtualAddress);
	printf("SizeOfRawData: %x\n", data->SizeOfRawData);
	printf("PointerToRawData: %x\n", data->PointerToRawData);
	printf("Characteristics %x\n", data->Characteristics);
	printf("\n");
}
void Print_IMAGE_RESOURCE_DIRECTORY(IMAGE_RESOURCE_DIRECTORY *data) {
	printf("NumberOfNamedEntries %x\n", data->NumberOfNamedEntries);
	printf("NumberOfIdEntries %x\n", data->NumberOfIdEntries);
}
void Print_IMAGE_RESOURCE_DIRECTORY_ENTRY(IMAGE_RESOURCE_DIRECTORY_ENTRY *data){
	printf("Id %x\n", data->Id);
	printf("OffsetToData %x\n", data->OffsetToData);
}
void Print_IMAGE_COR20_HEADER(IMAGE_COR20_HEADER *data) {
	printf("cb %x\n", data->cb);
	printf("MetaData VA %x Size %X\n", data->MetaData.VirtualAddress, data->MetaData.Size);
	printf("Resources VA %x Size %x\n", data->Resources.VirtualAddress, data->Resources.Size);
}
void Print_IMAGE_STREAM_HEADER(IMAGE_METADATA_ROOT *data) {
	printf("Signature %x\n", data->Signature);
	printf("Length %x\n", data->Length);
}
void Print_IMAGE_STREAM_HEADER(IMAGE_STREAM_HEADER *data) {
	printf("Offset %x\n", data->Offset);
	printf("Size %x\n", data->Size);
}


void PrintStringResource(uint32_t ptr, uint32_t size, char* buf) {
	auto tmpptr = reinterpret_cast<char*>(reinterpret_cast<uintptr_t>(buf) + static_cast<uintptr_t>(ptr));
	for (uint32_t i = 0; i < size; ++i) {
		if((9 <= tmpptr[i] && tmpptr[i] <= 12) || (32 <= tmpptr[i] && tmpptr[i] <= 126))
			printf("%c", tmpptr[i]);
	}
	printf("\n");
	
}
/*
pointが指している構造体のアドレス
0 := IMAGE_RESOURCE_DIRECTOR 1 := IMAGE_RESOURCE_DIRECTORY_ENTRY 2 := IMAGE_RESOURCE_DATA_ENTRY
*/
void PurseRsrcSection(uint32_t point, uint32_t flag, IMAGE_SECTION_HEADER* ptr, char* buf) {
	if(flag == 0){
		/* 現在の階層のエントリポイントの数 */
		auto tmpptr = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(reinterpret_cast<uintptr_t>(buf) + static_cast<uintptr_t>(point));
		uint32_t size = tmpptr->NumberOfNamedEntries + tmpptr->NumberOfIdEntries;
		point += sizeof(IMAGE_RESOURCE_DIRECTORY);
		for (uint32_t i = 0; i < size; ++i) {
			PurseRsrcSection(point + i * 0x8, 1, ptr, buf);
		}
	}else if(flag == 1) {
		auto tmpptr = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY*>(reinterpret_cast<uintptr_t>(buf) + static_cast<uintptr_t>(point));
		if(tmpptr->DataIsDirectory == 1) 
			PurseRsrcSection(tmpptr->OffsetToDirectory + ptr->PointerToRawData, 0, ptr, buf);
		else if(tmpptr->DataIsDirectory == 0)
			PurseRsrcSection(tmpptr->OffsetToDirectory + ptr->PointerToRawData, 2, ptr, buf);
	}else if(flag == 2) {
		auto tmpptr = reinterpret_cast<IMAGE_RESOURCE_DATA_ENTRY*>(reinterpret_cast<uintptr_t>(buf) + static_cast<uintptr_t>(point));
		PrintStringResource(tmpptr->OffsetToData + ptr->PointerToRawData - ptr->VirtualAddress, tmpptr->Size, buf);
		return;
	}
}

void PurseTextSectionMetadata(IMAGE_DATA_DIRECTORY data, IMAGE_SECTION_HEADER* SHptr, char* buf) {
	printf("======TextSectionMetadata======\n");
	uint32_t rva = data.VirtualAddress;
	uint32_t Start = rva + SHptr->PointerToRawData - SHptr->VirtualAddress; /* メタデータルートの先頭 */
	auto ptr1 = reinterpret_cast<IMAGE_METADATA_ROOT*>(reinterpret_cast<uintptr_t>(buf) + static_cast<uintptr_t>(Start));
	uint32_t Length = ptr1->Length;
	uint32_t Alignment = Length % 4 ? 4 - Length % 4 : 0;
	const uint32_t Offset = 0x12;

	/* 可変長構造体なので, メンバ変数Stremsの位置を計算 */
	auto ptr2 = reinterpret_cast<char*>(reinterpret_cast<uintptr_t>(buf) + static_cast<uintptr_t>(Start) + Offset + Length + Alignment);
	uint16_t Strems = ptr2[0] + ptr2[1] * 0x16; /* ストリームの数 */
	ptr2 += 2;
	auto streamptr = reinterpret_cast<IMAGE_STREAM_HEADER*>(ptr2);
	for (int i = 0; i < Strems; ++i) {
		uint32_t offset = streamptr->Offset, size = streamptr->Size;
		if(!strcmp(streamptr->Name, "#Strings") || !strcmp(streamptr->Name, "#US")) {
			PrintStringResource(Start + offset, size, buf);
		}
		uint32_t NameSize = strlen(streamptr->Name) + 1;
		uint32_t NameAlignment = NameSize % 4 ? 4 - NameSize % 4 : 0;
		streamptr = reinterpret_cast<IMAGE_STREAM_HEADER*>(reinterpret_cast<uintptr_t>(streamptr) + 0x8 + NameSize + NameAlignment);
	}
	printf("\n");
}

void PurseTextSectionResources(IMAGE_DATA_DIRECTORY data, IMAGE_SECTION_HEADER* ptr, char* buf) {
	printf("=====TextSectionResources======\n");
	uint32_t rva = data.VirtualAddress, size = data.Size;
	PrintStringResource(rva + ptr->PointerToRawData - ptr->VirtualAddress, size, buf);
	printf("\n");
}

void PuserTextSection(IMAGE_SECTION_HEADER* ptr, char* buf) {
	auto CLIheader = reinterpret_cast<IMAGE_COR20_HEADER*>(reinterpret_cast<uintptr_t>(buf) + static_cast<uintptr_t>(ptr->PointerToRawData) + 0x8);
	PurseTextSectionResources(CLIheader->Resources, ptr, buf);
	PurseTextSectionMetadata(CLIheader->MetaData, ptr, buf);
}

int main(int argc, char const *argv[]) {
	if(argc < 2){ 
		printf("Usage: ./a.out PEfile\n");
		return -1;
	}

	/* argv[1] で指定されたファイルをバイナリ形式かつ入力専用で開く */
	std::ifstream ifs(argv[1], std::ios::binary | std::ios::in);
	if(!ifs){ return -1; }
	ifs.seekg(0,std::ios::end);
	int size = static_cast<int>(ifs.tellg());
	ifs.seekg(0, std::ios_base::beg);
	char *buf = new char[size + 1];
	ifs.read(buf, size);

	/* ファイルの先頭から MS-DOSヘッダーが始まる */
	IMAGE_DOS_HEADER *PIMAGE_DOS_HEADER = reinterpret_cast<IMAGE_DOS_HEADER*>(buf);
	#ifdef DEBUG
		Print_IMAGE_DOS_HEADER(PIMAGE_DOS_HEADER);
	#endif

	/* ファイルの先頭からe_lfnewを足せば, NTヘッダーの先頭アドレス */
	IMAGE_NT_HEADERS *PIMAGE_NT_HEADERS = 
	reinterpret_cast<IMAGE_NT_HEADERS*>(buf + PIMAGE_DOS_HEADER->e_lfnew);
	#ifdef DEBUG
		Print_IMAGE_NT_HEADERS(PIMAGE_NT_HEADERS);
	#endif

	/* セクションデータはNTヘッダーの直下にくる */
	IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER = 
	reinterpret_cast<IMAGE_SECTION_HEADER *>(reinterpret_cast<uintptr_t>(PIMAGE_NT_HEADERS) + reinterpret_cast<uintptr_t>(sizeof(IMAGE_NT_HEADERS)));
	/* セクションの数だけ順番に見ていく */
	int SectionSize = PIMAGE_NT_HEADERS->FileHeader.NumberOfSections;
	for (int i = 0; i < SectionSize; ++i) {
		#ifdef DEBUG
			Print_IMAGE_SECTION_HEADER(PIMAGE_SECTION_HEADER);
		#endif
		if(!strcmp(PIMAGE_SECTION_HEADER->Name, ".text"))
			PuserTextSection(PIMAGE_SECTION_HEADER, buf);
		else if (!strcmp(PIMAGE_SECTION_HEADER->Name, ".rsrc")){
			printf("======ResourcesDirectory=====\n");
			PurseRsrcSection(PIMAGE_SECTION_HEADER->PointerToRawData, 0, PIMAGE_SECTION_HEADER, buf);
			printf("\n");
		}
		PIMAGE_SECTION_HEADER++;
	}

	delete[] buf;
	return 0;
}
