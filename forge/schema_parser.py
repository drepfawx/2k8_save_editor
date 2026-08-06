"""schema_parser.py -- parser for the POP0.schema binary format (class/field layout descriptions).

Format (little-endian, sequential):
  "SCHM" | u32 version(==2) | u32 | u64 | u64 | u8 | u32 filesize | u32 type_count
  per type: u32 A(nameHash) | u32 B | u64 C | u32 count1 | u32 count2
            count1 * field {u32 flags, u32 name_hash, u64 (type_hash low32 | trailer high32)}
            count2 * {u32 X, u32 count3, count3 * {u32, u32}}        (list B)
  then extra list: u32 cnt, cnt * {u32 X, u32 count3, count3 * {u32,u32}}
  then name table: u32 cnt, cnt * {u32 hash, cstring name}
"""
import os, struct, json

# Override with $POP0_SCHEMA_PATH if POP0.schema lives somewhere other than this directory.
PATH = os.environ.get('POP0_SCHEMA_PATH', 'POP0.schema')

class R:
    def __init__(s, d): s.d=d; s.p=0
    def u32(s): v=struct.unpack_from('<I',s.d,s.p)[0]; s.p+=4; return v
    def u64(s): v=struct.unpack_from('<Q',s.d,s.p)[0]; s.p+=8; return v
    def u8(s): v=s.d[s.p]; s.p+=1; return v
    def cstr(s):
        e=s.d.index(b'\0',s.p); v=s.d[s.p:e].decode('latin1'); s.p=e+1; return v

def parse(path=PATH):
    d=open(path,'rb').read()
    r=R(d)
    assert d[:4]==b'SCHM'; r.p=4
    ver=r.u32(); assert ver==2, ver
    r.u32(); r.u64(); r.u64(); r.u8(); filesize=r.u32(); count=r.u32()
    types=[]
    for i in range(count):
        A=r.u32(); B=r.u32(); C=r.u64(); c1=r.u32(); c2=r.u32()
        fields=[]
        for _ in range(c1):
            flags=r.u32(); nameh=r.u32(); tc=r.u64()
            fields.append((flags, nameh, tc & 0xffffffff, tc>>32))
        listB=[]
        for _ in range(c2):
            X=r.u32(); c3=r.u32(); sub=[(r.u32(), r.u32()) for _ in range(c3)]
            listB.append((X, sub))
        types.append({"A":A,"B":B,"C":C,"fields":fields,"listB":listB})
    # extra list
    ce=r.u32()
    extra=[]
    for _ in range(ce):
        X=r.u32(); c3=r.u32(); sub=[(r.u32(), r.u32()) for _ in range(c3)]
        extra.append((X,sub))
    # name table
    nc=r.u32()
    names={}
    for _ in range(nc):
        h=r.u32(); nm=r.cstr(); names[h]=nm
    return d, filesize, types, extra, names, r.p

if __name__=="__main__":
    d,filesize,types,extra,names,endp=parse()
    print(f"file={len(d)} declared_filesize={filesize} parsed_to={endp} ({'CLEAN END' if endp==len(d) else 'MISMATCH'})")
    print(f"types={len(types)} extra={len(extra)} names={len(names)}")
