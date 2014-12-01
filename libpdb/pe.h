#ifndef __PE_H__
#define __PE_H__

typedef union Guid
{
	struct
	{
		uint32_t data1;
		uint16_t data2;
		uint16_t data3;
		uint8_t data4[8];
	};
	uint8_t bytes[16];
} Guid;

typedef struct PeFile PeFile;
PeFile* PeOpen(const char* const filename);
void PeClose(PeFile* const peFile);

bool PeGetPdbData(PeFile* const pe, char* const pdbFilename,
	size_t pdbFilenameLen, Guid* const  pdbGuid, uint32_t* const pdbAge);

#endif /* __PE_H__ */
