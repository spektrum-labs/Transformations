"""Mirror of Token-Service codeexecutor.py's RestrictedPython namespace (lines 658-736)."""
import json, ast, re, math, itertools, functools, collections, datetime
from RestrictedPython import compile_restricted, safe_globals, safe_builtins
from RestrictedPython.Guards import guarded_iter_unpack_sequence, guarded_unpack_sequence
from RestrictedPython.Eval import default_guarded_getiter, default_guarded_getitem
from RestrictedPython.PrintCollector import PrintCollector
try:
    from RestrictedPython.Guards import guarded_inplacevar
except ImportError:
    # Exactly codeexecutor.py:133-163 -- this path is LIVE on the deployed
    # RestrictedPython, so the fallback is production behaviour, not a nicety.
    def guarded_inplacevar(op, x, y):
        ops = {'+=': lambda: x + y, '-=': lambda: x - y, '*=': lambda: x * y,
               '/=': lambda: x / y, '//=': lambda: x // y, '%=': lambda: x % y,
               '**=': lambda: x ** y, '&=': lambda: x & y, '|=': lambda: x | y,
               '^=': lambda: x ^ y, '>>=': lambda: x >> y, '<<=': lambda: x << y}
        if op not in ops:
            raise ValueError(f"Unsupported in-place operation: {op}")
        return ops[op]()

ALLOWED = {'json','ast','typing','copy','datetime','re','math','itertools','functools','collections'}
def safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name.split('.')[0] not in ALLOWED:
        raise ImportError(f"Import of '{name}' is not allowed")
    return __import__(name, globals, locals, fromlist, level)

def load(code, filename='<transformation>'):
    compiled = compile_restricted(code, filename, 'exec')
    rb = safe_builtins.copy()
    rb['__import__'] = safe_import
    rb.update({'dict':dict,'list':list,'str':str,'int':int,'float':float,'bool':bool,'tuple':tuple,
               'set':set,'len':len,'range':range,'enumerate':enumerate,'zip':zip,'sorted':sorted,
               'min':min,'max':max,'sum':sum,'any':any,'all':all,'abs':abs,'round':round,
               'isinstance':isinstance,'type':type})
    g = safe_globals.copy()
    g.update({'__name__':'__main__','__builtins__':rb,'json':json,'ast':ast,'re':re,
              'datetime':datetime,'math':math,'itertools':itertools,'functools':functools,
              'collections':collections,
              '_getiter_':default_guarded_getiter,'_getitem_':default_guarded_getitem,
              '_iter_unpack_sequence_':guarded_iter_unpack_sequence,
              '_unpack_sequence_':guarded_unpack_sequence,
              '_inplacevar_':guarded_inplacevar,'_print_':PrintCollector,'_write_':lambda x: x})
    ns = g.copy()
    code_obj = compiled.code if hasattr(compiled,'code') else compiled
    exec(code_obj, ns, ns)
    return ns
