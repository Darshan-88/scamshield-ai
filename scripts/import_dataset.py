"""Import UCI SMS Spam Collection, optionally checking a trusted SHA-256 digest."""
import argparse
import hashlib
import io
from pathlib import Path
from urllib.request import urlopen
from zipfile import ZipFile, is_zipfile
from tempfile import NamedTemporaryFile
import os

URL='https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip'
MAX=20*1024*1024
ROOT=Path(__file__).resolve().parents[1]

def install(raw, output, expected=None):
    if len(raw)>MAX: raise ValueError('Input too large')
    digest=hashlib.sha256(raw).hexdigest()
    if expected and digest.lower()!=expected.lower(): raise ValueError('SHA-256 mismatch')
    if is_zipfile(io.BytesIO(raw)):
        with ZipFile(io.BytesIO(raw)) as z:
            matches=[i for i in z.infolist() if Path(i.filename).name=='SMSSpamCollection' and not i.is_dir()]
            if len(matches)!=1 or matches[0].file_size>MAX: raise ValueError('Invalid dataset archive')
            raw=z.read(matches[0])  # read one member, never extract paths
    labels={'ham':0,'spam':0}; seen={}
    for line in raw.decode('utf-8-sig').splitlines():
        if not line.strip(): continue
        label,sep,message=line.partition('\t')
        if not sep or label not in labels or not message.strip(): raise ValueError('Expected ham/spam TSV rows')
        normalized=' '.join(message.casefold().split())
        if normalized in seen and seen[normalized]!=label: raise ValueError('Conflicting duplicate labels')
        if normalized not in seen: labels[label]+=1
        seen[normalized]=label
    if len(seen)<100 or min(labels.values())<10: raise ValueError('Dataset too small or missing class')
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    with NamedTemporaryFile(dir=output.parent,delete=False) as f:
        f.write(raw); temp=f.name
    try: os.replace(temp,output)
    finally:
        if os.path.exists(temp): os.unlink(temp)
    return {'unique_rows':len(seen),'classes':labels,'source_sha256':digest,'dataset_sha256':hashlib.sha256(raw).hexdigest()}

def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,help='Local UCI zip or TSV; omit to download official archive');p.add_argument('--sha256',help='Expected SHA-256 of source bytes');p.add_argument('--output',type=Path,default=ROOT/'data'/'SMSSpamCollection');a=p.parse_args()
    if a.source:
        with a.source.open('rb') as f: raw=f.read(MAX+1)
    else:
        with urlopen(URL,timeout=30) as r: raw=r.read(MAX+1)
    print(install(raw,a.output,a.sha256))

if __name__=='__main__': main()
