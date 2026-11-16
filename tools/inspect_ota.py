import io,json,struct,urllib.request,zipfile,zlib,pathlib
URL='https://gauss-componentotacostmanual-cn.allawnfs.com/remove-e90f34ae9c268bab4c505962e6ce071a/component-ota/26/01/15/b9e24307e1084eb0adbdc9784b7da3e1.zip'
OUT=pathlib.Path(__file__).resolve().parent
class Remote(io.RawIOBase):
 def __init__(self,url):
  self.url=url; self.pos=0
  with urllib.request.urlopen(urllib.request.Request(url,method='HEAD'),timeout=60) as r:self.size=int(r.headers['Content-Length'])
 def seekable(self):return True
 def readable(self):return True
 def seek(self,n,whence=0):
  self.pos=n if whence==0 else self.pos+n if whence==1 else self.size+n; return self.pos
 def tell(self):return self.pos
 def read(self,n=-1):
  if n<0:n=self.size-self.pos
  n=min(n,self.size-self.pos)
  if n<=0:return b''
  start=self.pos;end=start+n-1
  req=urllib.request.Request(self.url,headers={'Range':f'bytes={start}-{end}','Accept-Encoding':'identity'})
  with urllib.request.urlopen(req,timeout=120) as r:
   if r.status!=206 or not r.headers.get('Content-Range','').startswith(f'bytes {start}-{end}/'):raise ValueError(f'Range not respected: {r.status} {r.headers}')
   data=r.read(n+1)
  if len(data)!=n:raise ValueError('short or overlong range')
  self.pos+=n;return data

def varint(b,p):
 v=0;s=0
 while True:
  x=b[p];p+=1;v|=(x&127)<<s
  if x<128:return v,p
  s+=7

def proto(b):
 p=0;d={}
 while p<len(b):
  k,p=varint(b,p);f=k>>3;w=k&7
  if w==0:v,p=varint(b,p)
  elif w==2:n,p=varint(b,p);v=b[p:p+n];p+=n
  elif w==1:v=b[p:p+8];p+=8
  elif w==5:v=b[p:p+4];p+=4
  else:raise ValueError(w)
  d.setdefault(f,[]).append(v)
 return d

def main():
 r=Remote(URL);z=zipfile.ZipFile(r)
 entries=[{'name':i.filename,'size':i.file_size,'compressed':i.compress_size,'method':i.compress_type,'offset':i.header_offset} for i in z.infolist()]
 (OUT/'zip-entries.json').write_text(json.dumps(entries,indent=2))
 for i in z.infolist():
  if i.file_size<2_000_000 and ('metadata' in i.filename or 'payload_properties' in i.filename):
   data=z.read(i);(OUT/i.filename.replace('/','_')).write_bytes(data);print(i.filename, data[:4000].decode(errors='replace'),flush=True)
 i=z.getinfo('payload.bin')
 if i.compress_type!=0:raise ValueError('payload compressed')
 r.seek(i.header_offset);h=r.read(30);nl,xl=struct.unpack_from('<HH',h,26);base=i.header_offset+30+nl+xl
 r.seek(base);h=r.read(24);magic,version,ms,ss=struct.unpack('>4sQQI',h)
 if magic!=b'CrAU' or version!=2:raise ValueError((magic,version))
 m=r.read(ms);(OUT/'payload-manifest.pb').write_bytes(m);d=proto(m);bs=d.get(3,[4096])[0];data_base=base+24+ms+ss
 summary={'url':URL,'zip_size':r.size,'payload_base':base,'data_base':data_base,'block_size':bs,'partitions':[]}
 for raw in d.get(13,[]):
  p=proto(raw);name=p[1][0].decode();ops=[]
  for op in p.get(8,[]):
   q=proto(op);ops.append({'type':q.get(1,[None])[0],'offset':q.get(2,[0])[0],'length':q.get(3,[0])[0],'dst':[{'start':proto(e).get(1,[0])[0],'blocks':proto(e).get(2,[0])[0]} for e in q.get(6,[])]})
  pi=proto(p[7][0]) if 7 in p else {}
  row={'name':name,'size':pi.get(1,[None])[0],'sha256':pi.get(2,[b''])[0].hex(),'has_old':6 in p,'operations':ops};summary['partitions'].append(row)
  print(name,row['size'],len(ops),'types',sorted(set(o['type'] for o in ops)),flush=True)
 (OUT/'payload-summary.json').write_text(json.dumps(summary,indent=2))
if __name__=='__main__':main()
