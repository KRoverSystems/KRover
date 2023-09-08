#ifndef _INTER_FACE_H__
#define _INTER_FACE_H__

/********************************************export for external**********************************/
#ifdef __cplusplus
extern "C" {
#endif

#define EXPORT_ME

EXPORT_ME bool oasis_lib_init(const char *elf_file, ulong base_address);
EXPORT_ME void oasis_lib_fini(void);

EXPORT_ME bool DeclareSymbolicObject(ulong address, ulong size);

struct pt_regs;
EXPORT_ME bool StartExecutionAt(struct pt_regs *regs);

#ifdef __cplusplus
}
#endif

/********************************************interfaces for internal******************************/

bool SymbolicQuery(void *instruction);
bool symExecutor(void *arg);

#endif  // !_INTER_FACE_H__
