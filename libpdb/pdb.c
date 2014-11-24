/*
Copyright (c) 2010 Ryan Salsamendi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

I would like to thank and give credit to the following references I consulted while
writing this lib:

http://moyix.blogspot.com/2007/08/pdb-stream-decomposition.html
http://undocumented.rawol.com/ (Sven Boris Schreiber's site, of Undocumented Windows 2000 Secrets fame).
http://pierrelib.pagesperso-orange.fr/exec_formats/MS_Symbol_Type_v1.0.pdf (Old backup of MS COFF documentation)
http://ccimetadata.codeplex.com/ Microsoft Common Compiler Infrastructure Metadata API

*/


#include <string.h>
#include <errno.h>

#include "pdb.h"

const char PDB_SIGNATURE_V2[] = "Microsoft C/C++ program database 2.00\r\n";
const char PDB_SIGNATURE_V7[] = "Microsoft C/C++ MSF 7.00\r\n";

#define PDB_HEADER_SIZE_V2 (sizeof(PDB_SIGNATURE_V2) + 4)
#define PDB_HEADEr_SIZE_V7 (sizeof(PDB_SIGNATURE_V7) + 5)


#ifdef WIN32
#define fseeko _fseeki64
#define ftello _ftelli64
#endif /* WIN32 */


struct PdbFile
{
	char* name; // file name
	FILE* file;
	uint8_t version; // version from the header (2 or 7 are known)
	uint32_t streamCount; // number of streams in the file
	uint32_t pageSize; // bytes per page
	uint32_t pageCount; // total file bytes / page bytes
	uint32_t flagPage;

	PdbStream* root;
	PdbStream* lastAccessed;
};


struct PdbStream
{
	PdbFile* pdb;
	uint16_t id; // The stream index
	uint32_t* pages; // The indices of the pages comprising the stream
	uint64_t currentOffset; // The current offset
	uint32_t pageCount; // Total pages in this stream
	uint32_t size; // Total bytes in the stream
};


static bool PdbCheckFileSize(PdbFile* pdb)
{
	off_t currentOffset;
	off_t fileSize;
	uint64_t expectedPages;

	// Don't divide by zero
	if (pdb->pageSize == 0)
		return false;

	// Preserve the current offset, we are going to validate the file size
	currentOffset = ftello(pdb->file);

	// Goto the end of the file
	if (fseeko(pdb->file, 0, SEEK_END))
		return false;

	fileSize = ftello(pdb->file);

	// Calculate the expected file size
	expectedPages = ((uint64_t)fileSize / pdb->pageSize)
		+ ((fileSize % pdb->pageSize) ? 1 : 0);

	// See if the size yields the expected number of pages
	if (expectedPages != pdb->pageCount)
		return false;

	// Return to the saved offset
	if (fseeko(pdb->file, currentOffset, SEEK_SET))
		return false;

	return true;
}


static uint32_t GetPageCount(PdbFile* pdb, uint32_t bytes)
{
	// Watch out for div0
	if (pdb->pageSize == 0)
		return 0;

	// Round up in cases where it isn't a multiple of the page size
	return (bytes / pdb->pageSize) + ((bytes % pdb->pageSize != 0) ? 1 : 0);
}


uint16_t PdbGetStreamCount(PdbFile* pdb)
{
	return pdb->streamCount;
}


static bool PdbStreamOpenRoot(PdbFile* pdb, uint16_t rootStreamPageIndex, uint32_t size)
{
	PdbStream* root = (PdbStream*)malloc(sizeof(PdbStream));
	size_t i;

	pdb->root = root;
	root->id = -1;
	root->pdb = pdb;
	root->currentOffset = 0;
	root->size = size;

	// Calculate the number of pages comprising the root stream
	root->pageCount = GetPageCount(pdb, size);

	// Allocate storage for the pdb's root page list
	root->pages = (uint32_t*)malloc(pdb->pageCount * sizeof(uint32_t));
	memset(root->pages, 0, pdb->pageCount * sizeof(uint32_t));

	// Follow yet another layer of indirection (don't be fooled by Sven's docs,
	// the root page index in the header points to the list of indices 
	// that comprise the root stream)

	// Go to the list of page indices that belong to the root stream
	if (fseeko(pdb->file, (rootStreamPageIndex * pdb->pageSize), SEEK_SET))
		return false;

	// Get the root stream pages
	for (i = 0; i < root->pageCount; i++)
	{
		if (pdb->version == 2)
		{
			if (fread(&root->pages[i], 1, 2, pdb->file) != 2)
				return false;
		}
		else if (pdb->version == 7)
		{
			if (fread(&root->pages[i], 1, 4, pdb->file) != 4)
				return false;
		}
	}

	if (root->pageCount)
	{
		// Locate the root stream
		if (!PdbStreamSeek(pdb->root, 0))
			return false;
		
		// Read the count of the streams in this file
		if (!PdbStreamRead(pdb->root, (uint8_t*)&pdb->streamCount, 4))
			return false;
	}

	return true;
}


static bool PdbSeekToStreamSize(PdbFile* pdb, uint16_t streamId)
{
	uint32_t streamSizesOffset;

	// Pass the stream count, and the stream sizes before the stream of interest
	streamSizesOffset = 4 + ((streamId - 1) * 4);

	// Locate the stream size
	if (!PdbStreamSeek(pdb->root, streamSizesOffset))
		return false;

	return true;
}


static bool PdbSeekToStreamPageDirectory(PdbFile* pdb, uint16_t streamId, uint32_t* streamSize)
{
	uint32_t directoriesBase; // The beginning of the directories in the root stream
	uint32_t streamDirectoryOffset; // The offset in the page directories for the stream of interest
	uint32_t offset; // The final offset to seek to
	uint16_t i;

	// Sanity check the stream id
	if (streamId >= pdb->streamCount)
		return false;

	// Seek to the beginning of the root stream (after the stream count)
	if (!PdbStreamSeek(pdb->root, 4))
		return false;

	*streamSize = 0;
	streamDirectoryOffset = 0;

	for (i = 0; i < streamId; i++)
	{
		uint32_t size;

		// Read each stream size
		if (!PdbStreamRead(pdb->root, (uint8_t*)&size, 4))
			return false;

		// Add the number of bytes needed to store the page
		// indices for the stream
		streamDirectoryOffset += (4 * GetPageCount(pdb, size));
	}

	// Read the size of the stream of interest
	if (!PdbStreamRead(pdb->root, (uint8_t*)streamSize, 4))
		return false;

	// The directories begin after the sizes
	directoriesBase = 4 + (pdb->streamCount * 4);
	offset = directoriesBase + streamDirectoryOffset;

	// Seek to the stream directory of interest
	if (!PdbStreamSeek(pdb->root, offset))
		return false;

	return true;
}


bool PdbStreamSeek(PdbStream* stream, uint64_t offset)
{
	if (stream->pageCount)
	{
		uint64_t page;
		uint64_t fileOffset;

		// Avoid div0
		if (stream->pdb->pageSize == 0)
			return false;

		// Sanity check the offset
		if (offset >= stream->size)
			return false;

		// Calculate the page number within the stream this offset appears at
		page = offset / stream->pdb->pageSize;

		// Use the stream page number to lookup the page index within the file and then 
		// to calculate the offset of the page within the file
		// It may not be an even multiple of page size, so add back the remainder
		fileOffset = (stream->pages[page] * stream->pdb->pageSize)
			+ (offset % stream->pdb->pageSize);

		// Goto the page containing the requested offset
		if (fseeko(stream->pdb->file, fileOffset, SEEK_SET))
			return false;

		// Update last accessed
		stream->pdb->lastAccessed = stream;

		// Update the current offset
		stream->currentOffset = offset;

		return true;
	}

	return false;
}


PdbStream* PdbStreamOpen(PdbFile* pdb, uint16_t streamId)
{
	PdbStream* stream;
	uint32_t i;

	stream = (PdbStream*)malloc(sizeof(PdbStream));
	stream->pdb = pdb;
	stream->id = streamId;

	// Seek to the stream info and get the page size
	if (!PdbSeekToStreamPageDirectory(pdb, streamId, &stream->size))
	{
		free(stream);
		return NULL;
	}

	// Calculate the number of pages needed and alloc storage for the page indices
	stream->pageCount = GetPageCount(pdb, stream->size);
	stream->pages = (uint32_t*)malloc(sizeof(uint32_t) * stream->pageCount);

	// Read in the page indices that make up the stream
	for (i = 0; i < stream->pageCount; i++)
	{
		if (!PdbStreamRead(pdb->root, (uint8_t*)&stream->pages[i], 4))
			return false;
	}

	// Seek to the first page of the stream
	if (!PdbStreamSeek(stream, 0))
	{
		free(stream);
		return NULL;
	}

	return stream;
}


void PdbStreamClose(PdbStream* stream)
{
	free(stream->pages);
	free(stream);
}


static bool PdbParseHeader(PdbFile* pdb)
{
	char buff[sizeof(PDB_SIGNATURE_V2) + 1];

	// First try to read the longer (older) signature
	if (fread(buff, 1, sizeof(PDB_SIGNATURE_V2), pdb->file) == sizeof(PDB_SIGNATURE_V2))
	{
		uint16_t rootStreamId;
		uint32_t rootSize;

		// See if we have a match
		if (memcmp(PDB_SIGNATURE_V2, buff, sizeof(PDB_SIGNATURE_V2) - 1) == 0)
		{
			pdb->version = 2;

			// Expecting [unknown byte]JG\0
			if (fread(buff, 1, 4, pdb->file) != 4)
				return false;

			// Read the size of the pages in bytes (Hopefully 0x400,0x800, or 0x1000)
			if (fread(&pdb->pageSize, 1, 4, pdb->file) != 4)
				return false;

			// Sven calls this "Start page", not sure what it's for
			if (fread(buff, 1, 2, pdb->file) != 2)
				return false;

			// Get the number of pages in the file
			if (fread(&pdb->pageCount, 1, 2, pdb->file) != 2)
				return false;

			// Get the number of bytes in the root stream
			if (fread(&rootSize, 1, 4, pdb->file) != 4)
				return false;

			// Read the total number of streams in the file
			if (fread(&pdb->streamCount, 1, 4, pdb->file) != 4)
				return false;

			// Get the page of the root stream directory
			if (fread(&rootStreamId, 1, 2, pdb->file) != 2)
				return false;

			if (!PdbStreamOpenRoot(pdb, rootStreamId, rootSize))
				return false;
		
			return true;
		}

		// Now check for the newer format
		if (memcmp(PDB_SIGNATURE_V7, buff, sizeof(PDB_SIGNATURE_V7) - 1) == 0)
		{
			pdb->version = 7;

			// We went past the end of the signature because the V2 sig is
			// larger than the V7 sig.
			if (fseeko(pdb->file, sizeof(PDB_SIGNATURE_V7) - 1, SEEK_SET))
				return false;

			// Expecting reserved bytes, something like [unknown byte]DS\0\0\0
			if (fread(buff, 1, 6, pdb->file) != 6)
				return false;

			// Read the size of the pages in bytes (Probably 0x400)
			if (fread(&pdb->pageSize, 1, 4, pdb->file) != 4)
				return false;
	
			// Get the flag page (an allocation table, 1 if the page is unused)
			if (fread(&pdb->flagPage, 1, 4, pdb->file) != 4)
				return false;

			// Get number of pages in the file
			if ((fread(&pdb->pageCount, 1, 4, pdb->file) != 4))
				return false;

			// Ensure that this matches the actual file size
			if (!PdbCheckFileSize(pdb))
				return false;

			// Get the root stream size (in bytes)
			if (fread(&rootSize, 1, 4, pdb->file) != 4)
				return false;

			// Pass reserved dword
			if (fread(buff, 1, 4, pdb->file) != 4)
				return false;

			// Read the page index that contains the root stream
			if (fread(&rootStreamId, 1, 2, pdb->file) != 2)
				return false;

			// Move past reserved data
			if (fread(buff, 1, 2, pdb->file) != 2)
				return false;

			// Open the root stream (the pdb now owns rootPages storage)
			if (!PdbStreamOpenRoot(pdb, rootStreamId, rootSize))
				return false;

			return true;
		}
	}

	return false;
}


PdbFile* PdbOpen(const char* name)
{
	// TODO:  Ensure the file is not writable by other processes while
	// we have it open to avoid potential memory corruption due to having some
	// parts of the file cached and others not (and no refresh mechanism)
	FILE* file = fopen(name, "rb");
	PdbFile* pdb;

	if (!file)
	{
		fprintf(stderr, "Failed to open pdb file.  OS reports: %s\n", strerror(errno));
		return NULL;
	}
	
	pdb = (PdbFile*)malloc(sizeof(PdbFile));

	// Initialize
	pdb->name = strdup(name);
	pdb->file = file;
	pdb->version = 0;
	pdb->streamCount = 0;
	pdb->pageSize = 0;
	pdb->pageCount = 0;
	pdb->lastAccessed = NULL;
	pdb->root = NULL;

	// Read the header and open the root stream
	if (!PdbParseHeader(pdb))
	{
		free(pdb->name);
		fclose(pdb->file);
		free(pdb);

		return NULL;
	}

	return pdb;
}


void PdbClose(PdbFile* pdb)
{
	fclose(pdb->file);
	free(pdb->name);
	free(pdb);
}


PdbFile* PdbStreamGetPdb(PdbStream* stream)
{
	return stream->pdb;
}


uint32_t PdbStreamGetSize(PdbStream* stream)
{
	return stream->size;
}


bool PdbStreamRead(PdbStream* stream, uint8_t* buff, uint64_t bytes)
{
	uint8_t* pbuff = buff;
	uint64_t bytesRemaining = bytes;
	size_t bytesLeftOnPage;
	size_t bytesToRead = (size_t)-1;
	uint32_t pageMask;

	// Ensure that the requested bytes don't run off the end of the stream
	if (stream->currentOffset + bytes > stream->size)
		return false;

	// Assume that if this is the last accessed stream, that
	// we are already at the current offset.  Otherwise make it so.
	if (stream->pdb->lastAccessed != stream)
	{
		// Some other stream was read last, seek to this stream
		if (!PdbStreamSeek(stream, stream->currentOffset))
			return false;

		stream->pdb->lastAccessed = stream;
	}

	// Calculate how many bytes are left on the current page, starting from the current offset
	bytesLeftOnPage = (stream->pdb->pageSize - (stream->currentOffset % stream->pdb->pageSize));

	pageMask = stream->pdb->pageSize - 1;

	// Now read the remaining pages
	while (bytesRemaining)
	{
		uint64_t newOffset;

		// We can only read a page at a time
		// The first page may be shorter if the current offset is not at the beginning of the page
		bytesToRead = ((size_t)bytesRemaining < bytesLeftOnPage)
			? (size_t)bytesRemaining : bytesLeftOnPage;

		if (fread(pbuff, 1, bytesToRead, stream->pdb->file) != bytesToRead)
			return false;

		pbuff += bytesToRead;
		bytesRemaining -= bytesToRead;

		// Seek to the next requested position
		newOffset = stream->currentOffset + bytesToRead;
		if (((stream->currentOffset & pageMask) + bytesToRead) >= stream->pdb->pageSize)
		{
			// We only need to seek if we are crossing a page boundary
			if (!PdbStreamSeek(stream, newOffset))
				return false;
		}
		stream->currentOffset = newOffset;

		// Subsequent reads begin at the page offset 0, so they
		// will read an entire page
		bytesLeftOnPage = stream->pdb->pageSize;
	}

	return true;
}
