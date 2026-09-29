//
//  m3_exec_defs.h
//
//  Created by Steven Massey on 5/1/19.
//  Copyright © 2019 Steven Massey. All rights reserved.
//

#ifndef m3_exec_defs_h
#define m3_exec_defs_h

#include "m3_core.h"

d_m3BeginExternC

#define m3MemData(mem)              (u8*)(((M3MemoryHeader*)(mem))+1)
#define m3MemRuntime(mem)           (((M3MemoryHeader*)(mem))->runtime)
#define m3MemInfo(mem)              (((M3MemoryHeader*)(mem))->memory)

#define d_m3BaseOpSig               pc_t _pc, m3stack_t _sp, M3MemoryHeader * _mem, m3reg_t _r0
#define d_m3BaseOpArgs              _sp, _mem, _r0
#define d_m3BaseOpAllArgs           _pc, _sp, _mem, _r0
#define d_m3BaseOpDefaultArgs       0
#define d_m3BaseClearRegisters      _r0 = 0;
#define d_m3BaseCstr                ""

#define d_m3ExpOpSig(...)           d_m3BaseOpSig, __VA_ARGS__
#define d_m3ExpOpArgs(...)          d_m3BaseOpArgs, __VA_ARGS__
#define d_m3ExpOpAllArgs(...)       d_m3BaseOpAllArgs, __VA_ARGS__
#define d_m3ExpOpDefaultArgs(...)   d_m3BaseOpDefaultArgs, __VA_ARGS__
#define d_m3ExpClearRegisters(...)  d_m3BaseClearRegisters; __VA_ARGS__

#if d_m3HasFloat
#  define d_m3OpSig                 d_m3ExpOpSig            (f64 _fp0)
#  define d_m3OpArgs                d_m3ExpOpArgs           (_fp0)
#  define d_m3OpAllArgs             d_m3ExpOpAllArgs        (_fp0)
#  define d_m3OpDefaultArgs         d_m3ExpOpDefaultArgs    (0.)
#  define d_m3ClearRegisters        d_m3ExpClearRegisters   (_fp0 = 0.;)
#else
#  define d_m3OpSig                 d_m3BaseOpSig
#  define d_m3OpArgs                d_m3BaseOpArgs
#  define d_m3OpAllArgs             d_m3BaseOpAllArgs
#  define d_m3OpDefaultArgs         d_m3BaseOpDefaultArgs
#  define d_m3ClearRegisters        d_m3BaseClearRegisters
#endif


#define d_m3RetSig                  static inline m3ret_t vectorcall
#if (d_m3EnableOpProfiling || d_m3EnableOpTracing)
typedef m3ret_t(vectorcall* IM3Operation)(d_m3OpSig, cstr_t i_operationName);
#  define d_m3Op(NAME)              M3_NO_UBSAN d_m3RetSig op_##NAME (d_m3OpSig, cstr_t i_operationName)

#  define nextOpImpl()              ((IM3Operation)(* _pc))(_pc + 1, d_m3OpArgs, __FUNCTION__)
#  define jumpOpImpl(PC)            ((IM3Operation)(*  PC))( PC + 1, d_m3OpArgs, __FUNCTION__)
#else
typedef m3ret_t(vectorcall* IM3Operation)(d_m3OpSig);
#  define d_m3Op(NAME)              M3_NO_UBSAN d_m3RetSig op_##NAME (d_m3OpSig)

#  define nextOpImpl()              ((IM3Operation)(* _pc))(_pc + 1, d_m3OpArgs)
#  define jumpOpImpl(PC)            ((IM3Operation)(*  PC))( PC + 1, d_m3OpArgs)
#endif

#ifndef d_m3IterativeDispatch
#  define d_m3IterativeDispatch     0
#endif

#if d_m3IterativeDispatch
#  if d_m3EnableOpProfiling || d_m3EnableOpTracing
#    error "Iterative dispatch does not support opcode tracing/profiling"
#  endif

// On Xtensa GCC, `return nextOpImpl()` becomes callx8 + retw rather than a
// sibling call. A long Wasm function then consumes one native stack frame per
// opcode. This trampoline keeps the op signature and trap return contract,
// while retaining a native frame only for actual Wasm calls/blocks.
typedef struct M3DispatchState {
    pc_t pc;
    m3stack_t sp;
    M3MemoryHeader *mem;
    m3reg_t r0;
#  if d_m3HasFloat
    f64 fp0;
#  endif
} M3DispatchState;

// EvilKey invokes this interpreter from its one Apps worker. Save/restore the
// pointer for a nested Wasm call or initializer expression on that worker.
extern M3DispatchState *m3_dispatch_state;
extern const char m3_dispatch_again;

static inline m3ret_t m3_DispatchContinue(pc_t pc, m3stack_t sp,
                                           M3MemoryHeader *mem, m3reg_t r0
#  if d_m3HasFloat
                                           , f64 fp0
#  endif
                                           )
{
    M3DispatchState *state = m3_dispatch_state;
    if (M3_UNLIKELY(!state)) return "iterative dispatch context unavailable";
    state->pc = pc;
    state->sp = sp;
    state->mem = mem;
    state->r0 = r0;
#  if d_m3HasFloat
    state->fp0 = fp0;
#  endif
    return &m3_dispatch_again;
}

static inline m3ret_t m3_ExecuteDispatch(pc_t pc, m3stack_t sp,
                                          M3MemoryHeader *mem, m3reg_t r0
#  if d_m3HasFloat
                                          , f64 fp0
#  endif
                                          )
{
    M3DispatchState state = { .pc = pc, .sp = sp, .mem = mem, .r0 = r0
#  if d_m3HasFloat
                              , .fp0 = fp0
#  endif
                            };
    M3DispatchState *previous = m3_dispatch_state;
    m3_dispatch_state = &state;
    m3ret_t result;
    do {
        pc_t next = state.pc;
        IM3Operation op = (IM3Operation)*next;
#  if d_m3HasFloat
        result = op(next + 1, state.sp, state.mem, state.r0, state.fp0);
#  else
        result = op(next + 1, state.sp, state.mem, state.r0);
#  endif
    } while (result == &m3_dispatch_again);
    m3_dispatch_state = previous;
    return result;
}

#  if d_m3HasFloat
#    define d_m3DispatchArgs(PC)    (PC), _sp, _mem, _r0, _fp0
#  else
#    define d_m3DispatchArgs(PC)    (PC), _sp, _mem, _r0
#  endif
#  define nextOpDirect()            return m3_DispatchContinue(d_m3DispatchArgs(_pc))
#  define jumpOpDirect(PC)          return m3_DispatchContinue(d_m3DispatchArgs((pc_t)(PC)))
#  define d_m3ExecuteNext()         m3_ExecuteDispatch(d_m3DispatchArgs(_pc))
#  define d_m3ExecuteJump(PC)       m3_ExecuteDispatch(d_m3DispatchArgs((pc_t)(PC)))
#else
#  define nextOpDirect()            M3_MUSTTAIL return nextOpImpl()
#  define jumpOpDirect(PC)          M3_MUSTTAIL return jumpOpImpl((pc_t)(PC))
#  define d_m3ExecuteNext()         nextOpImpl()
#  define d_m3ExecuteJump(PC)       jumpOpImpl(PC)
#endif

#if (d_m3EnableOpProfiling || d_m3EnableOpTracing)
d_m3RetSig RunCode (d_m3OpSig, cstr_t i_operationName)
#else
d_m3RetSig RunCode (d_m3OpSig)
#endif
{
#if d_m3IterativeDispatch
    return m3_ExecuteDispatch(d_m3DispatchArgs(_pc));
#else
    nextOpDirect();
#endif
}

d_m3EndExternC

#endif // m3_exec_defs_h
