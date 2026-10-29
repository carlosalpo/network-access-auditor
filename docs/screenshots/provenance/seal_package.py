"""Create content manifests after capture/review. Run only on an unsealed working copy."""
import datetime
import hashlib
import json
import struct
from pathlib import Path

P = Path(__file__).resolve().parents[1]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,data): p.write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n')
def size(p):
    raw=p.read_bytes(); assert raw[:2]==b'\xff\xd8'; i=2
    while i<len(raw):
        assert raw[i]==255
        marker=raw[i+1]; i+=2
        length=struct.unpack('>H',raw[i:i+2])[0]
        if marker in [0xc0,0xc1,0xc2]:
            height,width=struct.unpack('>HH',raw[i+3:i+7]); return width,height
        i+=length
    raise ValueError('Missing JPEG dimensions')

pages=json.loads((P/'provenance/page-sources.json').read_text())
captures=[]
for page in pages:
    p=P/'images'/f'{page["id"]}.jpg'
    width,height=size(p)
    sources=page['sources']+[page['viewer'],'viewer/style.css','provenance/build_viewer.py']
    captures.append(dict(id=page['id'],image=p.relative_to(P).as_posix(),sha256=sha(p),
        width=width,height=height,mime_type='image/jpeg',
        captured_file_modified_at_utc=datetime.datetime.fromtimestamp(p.stat().st_mtime,datetime.timezone.utc).isoformat(),
        method='CUA tab.screenshot({fullPage:true}); original returned bytes saved without transformation',
        browser='Codex in-app browser',viewport=dict(width=1280,height=720,override=False),
        selection=page['selection'],portfolio_selected=page['id'] in ['01-risk-witness','03-mab-expiration'],
        visual_review=dict(passed=True,all_rows_visible=True,footer_visible=True,no_horizontal_clipping=True,
                           not_product_ui_label_visible=True,personal_paths_or_credentials_visible=False),
        sources=[dict(path=s,sha256=sha(P/s)) for s in sources]))

files={p.relative_to(P).as_posix():dict(bytes=p.stat().st_size,sha256=sha(p))
       for p in sorted(P.rglob('*')) if p.is_file() and p.relative_to(P).as_posix() not in ['manifest.json','SHA256SUMS']}
manifest=dict(schema_version=1,project='Network Access Auditor',version='0.1.0',
    repository='https://github.com/carlosalpo/network-access-auditor',
    commit='bf76b4bf12d0c08422ed98ca05e024d9557f737b',capture_date='2026-10-29',timezone='America/Tegucigalpa',
    execution='Independent local run; no remote CI attestation',scope='offline-normalized-nac-model',
    provenance='Public hand-authored synthetic examples; no Cisco ISE export',
    limitations=['No ISE connection, native import or complete emulation','No authentication or network enforcement',
                 'Trust and profile access are declarations','Modeled findings do not establish real exploitation',
                 'No findings does not certify security','A current MAB exception does not waive baseline controls'],
    integrity='Unsigned SHA-256 content checks; not authentication. SHA256SUMS includes this manifest and excludes itself.',
    state='Frozen handoff package; no publication performed',captures=captures,files=files)
write(P/'manifest.json',manifest)
paths=[p for p in sorted(P.rglob('*')) if p.is_file() and p.name!='SHA256SUMS']
(P/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.relative_to(P).as_posix()+'\n' for p in paths))
print(json.dumps(dict(captures=len(captures),hashed_files=len(paths),manifest_sha256=sha(P/'manifest.json'))))
