#define BLOCK_SIZE   1024
#define SHDR_SIZE    40
#define SHDR_START_OFFSET  0x20
#define TEXT_SHDR_ID 0x00380000
#define MAIN_SEQ  0xe1a0c00d
#define OFFSET_ID 0x10000
#define LDR_START 0xe59f0000
#define LDR_STOP  0xe59fffff
#define SCT_INTERP   0
#define SCT_HASH     1
#define SCT_DYNSYM   2
#define SCT_DYNSTR  3
#define SCT_REL_PLT  4
#define SCT_INIT   5
#define SCT_PLT   6
#define SCT_TEXT  7
#define SCT_FINI  8
#define SCT_RODATA   9
#define SCT_EH_FRAME 10
#define SCT_INIT_FRAME  11
#define SCT_FINI_ARRAY  12
#define SCT_JCR   13
#define SCT_DYNAMIC  14
#define SCT_GOT   15
#define SCT_DATA  16
#define SCT_BSS   17
#define SCT_COMMENT  18
#define SCT_ARM_ATTRIBUTES 19
#define SCT_SHSTRTAB   20
#define NB_SHDR   21
#define DYNSYM_ENTRY_SIZE 16
#define REL_PLT_ENTRY_SIZE 8
#define DYNAMIC_ENTRY_SIZE 8
#define ARM_INSTRUCTION_SIZE 4
#define MAX_STRING_SIZE 15
#define ADDR_ID 0x8000
char *shdrNames[] = {".interp", ".hash", ".dynsym", ".dynstr", ".rel.plt", ".init", 
                        ".plt", ".text", ".fini", ".rodata", ".eh_frame", ".init_array", 
                        ".fini_array", ".jcr", ".dynamic", ".got", ".data", ".bss", 
                        ".comment", ".ARM.attributes", ".shstrtab"
                     };
