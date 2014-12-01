#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#ifdef WIN32
#include <Windows.h>
#else /* Linux */
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif /* WIN32 */

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

typedef enum IMAGE_DIRECTORY_ENTRY
{
	IMAGE_DIRECTORY_ENTRY_EXPORT = 0,
	IMAGE_DIRECTORY_ENTRY_IMPORT = 1,
	IMAGE_DIRECTORY_ENTRY_RESOURCE = 2,
	IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3,
	IMAGE_DIRECTORY_ENTRY_CERTIFICATE = 4,
	IMAGE_DIRECTORY_ENTRY_RELOCATION = 5,
	IMAGE_DIRECTORY_ENTRY_DEBUG = 6,
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7,
	IMAGE_DIRECTORY_ENTRY_GLOBAL = 8,
	IMAGE_DIRECTORY_ENTRY_TLS = 9,
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10,
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11,
	IMAGE_DIRECTORY_ENTRY_IAT = 12,
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT_DESCRIPTOR = 13,
	IMAGE_DIRECTORY_ENTRY_CLR_HEADER = 14,
	IMAGE_DIRECTORY_ENTRY_RESERVED = 15,
} IMAGE_DIRECTORY_ENTRY;

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

typedef enum IMAGE_DEBUG_TYPE
{
	IMAGE_DEBUG_TYPE_UNKNOWN = 0,
	IMAGE_DEBUG_TYPE_COFF = 1,
	IMAGE_DEBUG_TYPE_CODEVIEW = 2,
	IMAGE_DEBUG_TYPE_FPO = 3,
	IMAGE_DEBUG_TYPE_MISC = 4,
	IMAGE_DEBUG_TYPE_EXCEPTION = 5,
	IMAGE_DEBUG_TYPE_FIXUP = 6,
	IMAGE_DEBUG_TYPE_BORLAND = 9
} IMAGE_DEBUG_TYPE;

typedef struct IMAGE_DEBUG_DIRECTORY
{
  uint32_t Characteristics;
  uint32_t TimeDateStamp;
  uint16_t MajorVersion;
  uint16_t MinorVersion;
  uint32_t Type;
  uint32_t SizeOfData;
  uint32_t AddressOfRawData;
  uint32_t PointerToRawData;
} IMAGE_DEBUG_DIRECTORY;

struct PeFile
{
#ifdef WIN32
	HANDLE hFileMapping;
#else
	int fd;
#endif /* WIN32 */
	const void* data;
	const char* name;
	size_t len;
};

PeFile* PeOpen(const char* const filename)
{
	const IMAGE_DOS_HEADER* dosHeader;
	const IMAGE_NT_HEADERS* ntHeaders;
	PeFile* pe;
#ifdef WIN32
	HANDLE hFileMapping;
	LARGE_INTEGER len;
#else
	int fd;
	struct stat statData;
#endif /* WIN32 */

	pe = (PeFile*)calloc(1, sizeof(PeFile));
	pe->name = strdup(filename);

#ifdef WIN32
	hFileMapping = OpenFileMapping(FILE_MAP_READ, FALSE, filename);
	if (!hFileMapping)
	{
		fprintf(stderr, "Failed to open pe file. OS reports: %s\n",
			strerror(errno));
		return NULL;
	}
	pe->hFileMapping = hFileMapping;

	if (!GetFileSizeEx(filename, &len))
	{
		fprintf(stderr, "Failed to get pe file size. OS reports: %s\n", strerror(errno));
		return NULL;
	}
	pe->len = (size_t)len;

	pe->data = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, pe->len);
#else /* Linux */
	fd = open(filename, O_RDONLY);
	if (fd == -1)
	{

		fprintf(stderr, "Failed to open pe file. OS reports: %s\n",
			strerror(errno));
		return NULL;
	}

	if (fstat(fd, &statData) == -1)
	{
		fprintf(stderr, "Failed to stat pe file. OS reports: %s\n",
			strerror(errno));
	}
	pe->len = (size_t)statData.st_size;

	pe->data = mmap(NULL, pe->len, PROT_READ, MAP_PRIVATE, fd, 0);
#endif /* WIN32 */
	if (!pe->data)
	{
		fprintf(stderr, "Could not map the pe file.\n");
		PeClose(pe);
		return NULL;
	}

	if (pe->len < (sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)))
	{
		fprintf(stderr, "Not a valid pe file. Not enough data.\n");
		PeClose(pe);
		return NULL;
	}

	dosHeader = (IMAGE_DOS_HEADER*)pe->data;
	if (dosHeader->e_magic != 0x4d5a)
	{
		fprintf(stderr, "Not a PE file. MS DOS header magic doesn't match.\n");
		PeClose(pe);
		return NULL;
	}

	ntHeaders = (void*)(pe->data + dosHeader->e_lfanew);
	if (((void*)ntHeaders) > (pe->data + pe->len))
	{
		fprintf(stderr, "Could not seek to PE header.\n");
		PeClose(pe);
		return NULL;
	}

	if (ntHeaders->Signature != 0x50450000)
	{
		fprintf(stderr, "PE signature does not match.\n");
		PeClose(pe);
		return NULL;
	}

	return pe;
}


void PeClose(PeFile* const pe)
{
#ifdef WIN32
	if (pe->data)
		UnmapViewOfFile(pe->data);
	if (pe->hFileMapping)
		CloseHandle(pe->file);
#else /* Linux */
	if (pe->data)
		munmap((void*)pe->data, pe->len);
	if (pe->fd != -1)
		close(pe->fd);
#endif /* WIN32 */
	if (pe->name)
		free((void*)pe->name);
	free(pe);
}


static __inline bool CheckPointer(const PeFile* const pe,
	const void* const data, size_t len)
{
	if (data < pe->data)
		return false;
	if (data >= (pe->data + pe->len))
		return false;
	if ((data + len) >= (pe->data + pe->len))
		return false;
	return true;
}


static __inline bool CheckStringPointer(const PeFile* const pe,
	const char* const str)
{
	const char* c = str;

	// See if the first byte is even in the image.
	if (!CheckPointer(pe, str, 1))
		return false;

	// Now scan for a NULL byte or the end of the image, whichever
	// comes first.
	while ((*c) != '\0')
	{
		c++;
		if (c >= (char*)(pe->data + pe->len))
			return false;
	}

	return true;
}


bool PeGetPdbData(PeFile* const pe, char* const filename,
	size_t filenameLen, Guid* const guid, uint32_t* const age)
{
	const IMAGE_DOS_HEADER* const dosHeader
		= (IMAGE_DOS_HEADER*)pe->data;
	const IMAGE_NT_HEADERS* const ntHeaders
		= (IMAGE_NT_HEADERS*)(pe->data + dosHeader->e_lfanew);
	const IMAGE_FILE_HEADER* const fileHeader
		= &ntHeaders->FileHeader;
	const IMAGE_OPTIONAL_HEADER* const optHeader
		= (IMAGE_OPTIONAL_HEADER*)(fileHeader + 1);
	const IMAGE_DATA_DIRECTORY* dataDir;
	const IMAGE_DEBUG_DIRECTORY* debugDir;
	const uint8_t* pdbData;

	if (!CheckPointer(pe, optHeader, sizeof(IMAGE_OPTIONAL_HEADER)))
	{
		fprintf(stderr, "Failed to read pe optional header.\n");
		return false;
	}

	if (optHeader->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
	{
		fprintf(stderr, "Debug directory not present.\n");
		return false;
	}

	dataDir = &optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	debugDir = (IMAGE_DEBUG_DIRECTORY*)(pe->data + dataDir->VirtualAddress);
	if (!CheckPointer(pe, debugDir, sizeof(IMAGE_DEBUG_DIRECTORY)))
	{
		fprintf(stderr, "Debug directory not within image.\n");
		return false;
	}

	if (debugDir->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
	{
		fprintf(stderr, "Debug directory is not codeview data.\n");
		return false;
	}

	pdbData = (uint8_t*)(pe->data + debugDir->AddressOfRawData);
	if (!CheckPointer(pe, pdbData, 25)) // Minimum size of PDB70 data
	{
		fprintf(stderr, "PDB information not within image.\n");
		return false;
	}

	if (*(uint32_t*)pdbData == 0x4e423130)
	{
		// Check for NB10, which means this is PDB20 data
		memset(guid, 0, sizeof(Guid));
		guid->data1 = *(uint32_t*)(pdbData + 8);
		*age = *(uint32_t*)(pdbData + 12);

		// The image is potentially hostile, ensure the filename
		// is in the PE
		if (!CheckStringPointer(pe, (char*)(pdbData + 16)))
		{
			fprintf(stderr, "Pdb filename outside the image!\n");
			return false;
		}

		// Ensure NULL termination
		filename[filenameLen - 1] = '\0';
		strncpy(filename, (char*)(pdbData + 16), filenameLen - 1);

		return true;
	}
	else if (*(uint32_t*)pdbData == 0x52534453) // RSDS means PDB70
	{
		memcpy(guid->bytes, (pdbData + 4), sizeof(Guid));
		*age = *(uint32_t*)(pdbData + 20);

		// The image is potentially hostile, ensure the filename
		// is in the PE
		if (!CheckStringPointer(pe, (char*)(pdbData + 24)))
		{
			fprintf(stderr, "Pdb filename outside the image!\n");
			return false;
		}

		// Ensure NULL termination
		filename[filenameLen - 1] = '\0';
		strncpy(filename, (char*)(pdbData + 24), filenameLen - 1);

		return true;
	}
	else
	{
		// Unknown pdb info format
		fprintf(stderr, "Unknownpdb info format %.8x\n",
			*(uint32_t*)pdbData);
		return false;
	}
}


