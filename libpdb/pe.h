#ifndef __PE_H__
#define __PE_H__

typedef struct PeFile PeFile;
PeFile* PeOpen(const char* const filename);
void PeClose(PeFile* const peFile);

#endif /* __PE_H__ */
