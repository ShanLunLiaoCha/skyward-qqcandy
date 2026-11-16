import argparse,bz2,hashlib,json,lzma,pathlib,sys
from inspect_ota import Remote,proto,OUT,URL

def main():
 ap=argparse.ArgumentParser();ap.add_argument('partitions',nargs='+');args=ap.parse_args()
 summary=json.loads((OUT/'payload-summary.json').read_text());manifest=proto((OUT/'payload-manifest.pb').read_bytes());bs=summary['block_size'];remote=Remote(URL)
 for raw in manifest[13]:
  p=proto(raw);name=p[1][0].decode()
  if name not in args.partitions:continue
  if 6 in p:raise ValueError(f'{name} requires source image; refuse delta')
  pi=proto(p[7][0]);size=pi[1][0];expected=pi[2][0]
  dest=OUT/'images'/f'{name}.img';dest.parent.mkdir(exist_ok=True)
  if dest.exists():
   with dest.open('rb') as f:ok=hashlib.file_digest(f,'sha256').digest()==expected
   if ok:print(f'{name}: verified existing image',flush=True);continue
  tmp=dest.with_suffix('.img.partial')
  with tmp.open('w+b') as f:
   f.truncate(size)
   for index,op in enumerate(p.get(8,[])):
    q=proto(op);typ=q[1][0];extents=[proto(e) for e in q.get(6,[])];length=sum(e[2][0]*bs for e in extents)
    if typ==6:data=b'\0'*length
    elif typ in (0,1,8):
     remote.seek(summary['data_base']+q.get(2,[0])[0]);blob=remote.read(q[3][0])
     if 8 not in q or hashlib.sha256(blob).digest()!=q[8][0]:raise ValueError(f'{name} op{index} hash failed')
     data=blob if typ==0 else bz2.decompress(blob) if typ==1 else lzma.decompress(blob)
    else:raise ValueError(f'unsupported op {typ}')
    if len(data)!=length:raise ValueError(f'{name} op{index} length mismatch')
    cursor=0
    for e in extents:
     n=e[2][0]*bs;f.seek(e[1][0]*bs);f.write(data[cursor:cursor+n]);cursor+=n
    print(f'{name}: {index+1}/{len(p.get(8,[]))}',flush=True)
   f.flush();f.seek(0)
   if hashlib.file_digest(f,'sha256').digest()!=expected:raise ValueError(f'{name} final hash failed')
  tmp.replace(dest);print(f'{name}: SHA256 {expected.hex()} OK',flush=True)
 missing=set(args.partitions)-{proto(p)[1][0].decode() for p in manifest[13]}
 if missing:raise ValueError(f'missing partitions {missing}')
if __name__=='__main__':main()
