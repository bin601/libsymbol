#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "pe.h"

// http://www.brokenthorn.com/Resources/OSDevPE.html
typedef struct IMAGE_DOS_HEADER  // DOS .EXE header
{
    uint16_t e_magic;		// must contain "MZ"
    uint16_t e_cblp;		// number of bytes on the last page of the file
    uint16_t e_cp;		// number of pages in file
    uint16_t e_crlc;		// relocations
    uint16_t e_cparhdr;		// size of the header in paragraphs
    uint16_t e_minalloc;	// minimum and maximum paragraphs to allocate
    uint16_t e_maxalloc;
    uint16_t e_ss;		// initial SS:SP to set by Loader
    uint16_t e_sp;
    uint16_t e_csum;		// checksum
    uint16_t e_ip;		// initial CS:IP
    uint16_t e_cs;
    uint16_t e_lfarlc;		// address of relocation table
    uint16_t e_ovno;		// overlay number
    uint16_t e_res[4];		// resevered
    uint16_t e_oemid;		// OEM id
    uint16_t e_oeminfo;		// OEM info
    uint16_t e_res2[10];	// reserved
    uint32_t e_lfanew;	// address of new EXE header
} IMAGE_DOS_HEADER;

typedef enum IMAGE_MACHINE_TYPE
{
	IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
	IMAGE_FILE_MACHINE_AM33	= 0x1d3,
	IMAGE_FILE_MACHINE_AMD6 = 0x8664,
	IMAGE_FILE_MACHINE_ARM = 0x1c0,
	IMAGE_FILE_MACHINE_ARMN = 0x1c4,
	IMAGE_FILE_MACHINE_ARM64 = 0xaa64,
	IMAGE_FILE_MACHINE_EBC = 0xebc,
	IMAGE_FILE_MACHINE_I386 = 0x14c,
	IMAGE_FILE_MACHINE_IA64 = 0x200,
	IMAGE_FILE_MACHINE_M32R = 0x9041,
	IMAGE_FILE_MACHINE_MIPS16 = 0x266,
	IMAGE_FILE_MACHINE_MIPSFPU = 0x366,
	IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466,
	IMAGE_FILE_MACHINE_POWERPC = 0x1f0,
	IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1,
	IMAGE_FILE_MACHINE_R4000 = 0x166,
	IMAGE_FILE_MACHINE_SH3 = 0x1a2,
	IMAGE_FILE_MACHINE_SH3DSP = 0x1a3,
	IMAGE_FILE_MACHINE_SH4 = 0x1a6,
	IMAGE_FILE_MACHINE_SH5 = 0x1a8,
	IMAGE_FILE_MACHINE_THUMB = 0x1c2,
	IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169
} IMAGE_MACHINE_TYPE;

typedef struct IMAGE_FILE_HEADER
{
    uint16_t Machine;
    uint16_t NumberOfSections; // Number of sections in section table
    uint32_t TimeDateStamp; // Date and time of program link
    uint32_t PointerToSymbolTable; // RVA of symbol table
    uint32_t NumberOfSymbols; // Number of symbols in table
    uint16_t SizeOfOptionalHeader; // Size of IMAGE_OPTIONAL_HEADER in bytes
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct IMAGE_DATA_DIRECTORY
{
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct IMAGE_OPTIONAL_HEADER
{
    uint16_t Magic; // not-so-magical number
    uint8_t MajorLinkerVersion; // linker version
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode; // size of .text in bytes
    uint32_t SizeOfInitializedData; // size of .bss (and others) in bytes
    uint32_t SizeOfUninitializedData; // size of .data,.sdata etc in bytes
    uint32_t AddressOfEntryPoint; // RVA of entry point
    uint32_t BaseOfCode; // base of .text
    uint32_t BaseOfData; // base of .data
    uint32_t ImageBase;	 // image base VA
    uint32_t SectionAlignment; // file section alignment
    uint32_t FileAlignment; // file alignment
    uint16_t MajorOperatingSystemVersion; // Windows specific. OS version required to run image
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;	 // version of program
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion; // Windows specific. Version of SubSystem
    uint16_t MinorSubsystemVersion;
    uint32_t Reserved1;
    uint32_t SizeOfImage; // size of image in bytes
    uint32_t SizeOfHeaders; // size of headers (and stub program) in bytes
    uint32_t CheckSum; // checksum
    uint16_t Subsystem; // Windows specific. subsystem type
    uint16_t DllCharacteristics; // DLL properties
    uint32_t SizeOfStackReserve; // size of stack, in bytes
    uint32_t SizeOfStackCommit; // size of stack to commit
    uint32_t SizeOfHeapReserve; // size of heap, in bytes
    uint32_t SizeOfHeapCommit; // size of heap to commit
    uint32_t LoaderFlags; // no longer used
    uint32_t NumberOfRvaAndSizes; // number of DataDirectory entries
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER;

typedef struct IMAGE_NT_HEADERS
{
  uint32_t Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS;

struct PeFile
{
	FILE* file;
	const char* name;
};

PeFile* PeOpen(const char* const filename)
{
	FILE* const file = fopen(filename, "rb");
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeaders;
	PeFile* pe;

	if (!file)
	{
		fprintf(stderr, "Failed to open pdb file.  OS reports: %s\n", strerror(errno));
		return NULL;
	}

	if (fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, file) != 1)
	{
		fprintf(stderr, "Not enough data to be a PE file.\n");
		fclose(file);
		return NULL;
	}

	if (dosHeader.e_magic != 0x4d5a)
	{
		fprintf(stderr, "Not a PE file. MS DOS header magic doesn't match.\n");
		fclose(file);
		return NULL;
	}

	if (fseeko(file, dosHeader.e_lfanew, SEEK_SET))
	{
		fprintf(stderr, "Could not seek to PE header.\n");
		fclose(file);
		return NULL;
	}

	if (fread(&ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, file) != 1)
	{
		fprintf(stderr, "Not enough data for PE header.\n");
		fclose(file);
		return NULL;
	}

	if (ntHeaders.Signature != 0x50450000)
	{
		fprintf(stderr, "PE signature does not match.\n");
		fclose(file);
		return NULL;
	}


	pe = (PeFile*)calloc(1, sizeof(PeFile));
	pe->file = file;
	pe->name = strdup(filename);

	return pe;
}


void PeClose(PeFile* const peFile)
{
	if (peFile->file)
		fclose(peFile->file);
	if (peFile->name)
		free((void*)peFile->name);
	free(peFile);
}


