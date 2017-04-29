#include <iostream>
#include <fstream>
#include <cstdio>

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
	uint32_t PointerToSymbolTable; // 0x0000 (Don't use)
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptopmalHeader; // IMAGE_OPTIONAL_HEADERのサイズ
	uint16_t Characteristics;
};
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
struct IMAGE_OPTIONAL_HEADER{
	// Standard field
	uint16_t Magic; // PE32(0x010b) PE64(0x020b)
	uint8_t  MajorLinkerVersion;
	uint8_t  MinorLinlerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint; // relative virtual address
	uint32_t BaseOfCode;
	uint32_t BaseOfData;

	// NT additional fields
	uint32_t ImageBase; // Load address
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage; // require to load image file size
	uint32_t SizeOfHeaders; // all headers size
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint32_t SizeOfStackReserve;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes; //0x10(IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
	// uint64_t Trash; //8byteのアライメント?が存在
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};


struct IMAGE_NT_HEADERS32 {
	uint32_t Signature; // Magic Number (0x50450000)
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
};

// IMAGE_SECTION_HEADER 's number = IMAGE_FILE_HEADER::NumberOfSections
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


void Print_IMAGE_DOS_HEADER(IMAGE_DOS_HEADER *data){
	printf("e_magic: %x\n", data->e_magic); //文字列として入力されるのものは出力がおかしい
	printf("e_lfnew: %x\n", data->e_lfnew);
}

void Print_IMAGE_NT_HEADERS32(IMAGE_NT_HEADERS32 *data){
	printf("Signature: %x\n", data->Signature); //出力が逆
	printf("Machine : %x\n", data->FileHeader.Machine);
	printf("NumberOfSections: %x\n", data->FileHeader.NumberOfSections);
	printf("Magic : %x\n", data->OptionalHeader.Magic);
	printf("ImageBase : %x\n", data->OptionalHeader.ImageBase);
	printf("SizeOfStackReserve: %x\n", data->OptionalHeader.SizeOfStackReserve);
	printf("SizeOfStackCommit: %x\n", data->OptionalHeader.SizeOfStackCommit);
	printf("LoaderFlags: %x\n", data->OptionalHeader.LoaderFlags);
	printf("NumberOfRvaAndSizes : %x\n", data->OptionalHeader.NumberOfRvaAndSizes);
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i){
		printf("%d VirtualAddress : %x size: %x\n", i,
			data->OptionalHeader.DataDirectory[i].VirtualAddress,
			data->OptionalHeader.DataDirectory[i].Size);
	}
}
void Print_IMAGE_SECTION_HEADER(IMAGE_SECTION_HEADER *data){
	printf("Name: %s\n", data->Name);
	printf("SizeOfRawData: %x\n", data->SizeOfRawData);
	printf("PointerToRawData; %x\n", data->PointerToRawData);
	printf("Characteristics %x\n", data->Characteristics);
}

int main(int argc, char const *argv[]){
	if(argc < 2){ return -1; }

	//バイナリ形式かつ入力専用で開く
	std::ifstream ifs(argv[1], std::ios::binary | std::ios::in);
	if(!ifs){ return -1; }
	//終端までシーク
	ifs.seekg(0,std::ios::end);
	//サイズ(現在位置)を取得
	int size = static_cast<int>(ifs.tellg());
	//先頭までシーク
	ifs.seekg(0, std::ios_base::beg);
	char *buf = new char[size + 1];
	ifs.read(buf, size);

	IMAGE_DOS_HEADER *PIMAGE_DOS_HEADER = reinterpret_cast<IMAGE_DOS_HEADER *>(buf);
	Print_IMAGE_DOS_HEADER(PIMAGE_DOS_HEADER);

	IMAGE_NT_HEADERS32 *PIMAGE_NT_HEADERS32 = 
	reinterpret_cast<IMAGE_NT_HEADERS32 *>(buf + PIMAGE_DOS_HEADER->e_lfnew);
	Print_IMAGE_NT_HEADERS32(PIMAGE_NT_HEADERS32);

	printf("%p\n", buf);
	printf("%p\n", PIMAGE_DOS_HEADER);
	printf("%p\n", PIMAGE_NT_HEADERS32);
	int sizetype = sizeof(IMAGE_NT_HEADERS32);
	printf("addr sizetype %d\n", sizetype);
	// int addr = PIMAGE_NT_HEADERS32 + sizetype;
	// printf("%p\n", addr);
	IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER = 
	reinterpret_cast<IMAGE_SECTION_HEADER *>(reinterpret_cast<uintptr_t>(PIMAGE_NT_HEADERS32)
		+ reinterpret_cast<uintptr_t>(sizeof(IMAGE_NT_HEADERS32)));

	printf("%p\n", PIMAGE_NT_HEADERS32);
	printf("%p\n", PIMAGE_SECTION_HEADER);
	int SectionSize = PIMAGE_NT_HEADERS32->FileHeader.NumberOfSections;
	// printf("SectionSize %d\n", SectionSize);
	for (int i = 0; i < SectionSize; ++i){
		Print_IMAGE_SECTION_HEADER(PIMAGE_SECTION_HEADER);
		PIMAGE_SECTION_HEADER++;
	}
	/*
	for (int i = 0; i < size; ++i){
		printf("%x", buf[i]);
	}
	*/
	delete[] buf;
	return 0;
}