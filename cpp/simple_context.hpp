#include <stdint.h>
#include <string.h>

// #define DEBUG 1

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#define LOG(fmt, ...) fprintf(stderr, "rspcode_native: " fmt "\n", ##__VA_ARGS__);
#else
#define LOG(fmt, ...) \
    do {              \
    } while (0)
#endif

#define MIN(x, y) ((x) < (y) ? (x) : (y))

struct PAddrSpace {
    const char *name;
    uint32_t type;
};

struct PAddress {
    PAddrSpace space;
    uint64_t offset;
};

struct PVarnodeData {
    PAddrSpace space;
    uint64_t offset;
    int size;
    const char *reg_name;
};

#define ERROR_STR_SIZE 0x200
extern char error_str[];


typedef void *PContext;
typedef void *PDisassembly;
typedef void *PDisassemblyInstruction;
typedef void *PTranslation;
typedef void *PPcodeOp;

PContext create_context(const char *path);
void destroy_context(PContext ctx);
void reset_context(PContext ctx);
void context_set_variable_default(PContext ctx, const char *name, uint32_t val);

PDisassembly
disassemble(PContext ctx, const char *bytes, unsigned int num_bytes, uint64_t address, unsigned int max_instructions);

size_t get_disassembly_insn_count(PDisassembly disas);
PDisassemblyInstruction get_disassembly_insn(PDisassembly disas, size_t index);

void get_insn_address(PDisassemblyInstruction insn, PAddress *addr);
size_t get_insn_length(PDisassemblyInstruction insn);
const char *get_insn_mnem(PDisassemblyInstruction insn);
const char *get_insn_body(PDisassemblyInstruction insn);

PTranslation translate(PContext ctx,
                       const char *bytes,
                       unsigned int num_bytes,
                       uint64_t base_address,
                       unsigned int max_instructions,
                       uint32_t flags);
size_t get_translation_op_count(PTranslation trans);
PPcodeOp get_translation_op(PTranslation trans, size_t index);

uint32_t get_translation_op_opcode(PPcodeOp op);
bool get_translation_op_output(PPcodeOp op, PVarnodeData *outvar);
size_t get_translation_op_input_count(PPcodeOp op);
bool get_translation_op_input(PPcodeOp op, size_t index, PVarnodeData *invar);