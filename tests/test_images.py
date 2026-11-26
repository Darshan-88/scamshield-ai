import io
import shutil
import subprocess
from pathlib import Path

import pytest
import qrcode
from PIL import Image, ImageDraw, ImageFont
from fastapi.testclient import TestClient
from backend.main import app
from backend import images, integrations

client = TestClient(app)


def image_bytes(image, fmt='PNG'):
    buf = io.BytesIO()
    image.save(buf, format=fmt)
    return buf.getvalue()


def upload(data, mime='image/png'):
    return client.post('/api/image/extract', content=data, headers={'Content-Type': mime})


def qr_image(payload):
    return qrcode.make(payload).convert('RGB')


def text_image():
    font_candidates = [Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'), Path('C:/Windows/Fonts/arial.ttf'), Path('/System/Library/Fonts/Supplemental/Arial.ttf')]
    font_path = next((p for p in font_candidates if p.exists()), None)
    font = ImageFont.truetype(str(font_path), 44) if font_path else ImageFont.load_default(size=44)
    img = Image.new('RGB', (1050, 280), 'white')
    d = ImageDraw.Draw(img)
    d.text((35, 35), 'Your account is blocked.', font=font, fill='black')
    d.text((35, 110), 'Share your OTP immediately.', font=font, fill='black')
    d.text((35, 185), 'Update KYC now.', font=font, fill='black')
    return img


def test_capabilities():
    r = client.get('/api/image/capabilities')
    assert r.json()['max_bytes'] == 8*1024*1024 and r.json()['qr_available']
    assert r.json()['cloud_image_upload'] is False
    assert r.headers['cache-control'] == 'no-store'


def test_real_ocr_and_scan():
    if not images.ocr_command(): pytest.skip('Tesseract executable not installed')
    r = upload(image_bytes(text_image()))
    assert r.status_code == 200
    data = r.json()
    assert data['ocr_status'] == 'extracted'
    assert 'OTP' in data['text'] and 'blocked' in data['text']
    scan = client.post('/api/scan', json={'text':data['text'], 'mode':'screenshot'}).json()
    assert scan['score'] >= 60 and scan['level'] == 'high'
    assert r.headers['cache-control'] == 'no-store'


@pytest.mark.parametrize('payload,kind', [('https://example.com/','web_url'),('upi://pay?pa=demo@example&am=1','upi_payment'),('WIFI:T:WPA;S:Example;P:test-only;;','other')])
def test_real_qr(monkeypatch,payload,kind):
    monkeypatch.setattr(images,'ocr_command',lambda:None)
    r=upload(image_bytes(qr_image(payload)))
    assert r.status_code == 200
    data=r.json()
    assert data['ocr_status']=='not_installed' and data['qr_status']=='decoded'
    assert data['qr_codes']==[{'kind':kind,'value':payload}]


def test_multi_qr(monkeypatch):
    monkeypatch.setattr(images,'ocr_command',lambda:None)
    a=qr_image('https://example.com/one');b=qr_image('https://example.org/two')
    canvas=Image.new('RGB',(a.width+b.width+100,max(a.height,b.height)+80),'white')
    canvas.paste(a,(10,40));canvas.paste(b,(a.width+80,40))
    data=upload(image_bytes(canvas)).json()
    assert {q['value'] for q in data['qr_codes']}=={'https://example.com/one','https://example.org/two'}


def test_payment_signal():
    data=client.post('/api/scan',json={'text':'QR payload: upi://pay?pa=demo@example&am=1','mode':'screenshot'}).json()
    assert any('UPI payment' in f['label'] for f in data['findings'])
    assert any('QR code alone' in a for a in data['advice'])


def test_qr_url_inspection():
    data=client.post('/api/scan',json={'text':'QR payload: http://192.0.2.1/login','mode':'screenshot'}).json()
    assert data['rule_score']>=35 and data['reputation']['detected_urls']==1


@pytest.mark.parametrize('fmt,mime',[('PNG','image/png'),('JPEG','image/jpeg'),('WEBP','image/webp')])
def test_formats(monkeypatch,fmt,mime):
    monkeypatch.setattr(images,'ocr_command',lambda:None)
    r=upload(image_bytes(Image.new('RGB',(80,80),'white'),fmt),mime)
    assert r.status_code==200 and r.json()['qr_status']=='not_detected'


@pytest.mark.parametrize('body,mime,status', [(b'','image/png',422),(b'not an image','image/png',422),(b'<svg/>','image/svg+xml',415),(b'%PDF','application/pdf',415)])
def test_invalid(body,mime,status):
    assert upload(body,mime).status_code==status


def test_mime_mismatch():
    assert upload(image_bytes(Image.new('RGB',(10,10)),'JPEG'),'image/png').status_code==422


def test_oversize(monkeypatch):
    monkeypatch.setattr(images,'MAX_BYTES',100)
    assert upload(b'x'*101).status_code==413
    # No content-length: stream is also bounded.
    r=client.post('/api/image/extract',content=iter([b'x'*60,b'y'*60]),headers={'Content-Type':'image/png'})
    assert r.status_code==413


def test_dimensions(monkeypatch):
    monkeypatch.setattr(images,'MAX_PIXELS',99)
    assert upload(image_bytes(Image.new('RGB',(10,10)))).status_code==422


def test_animated():
    buf=io.BytesIO();Image.new('RGB',(20,20),'white').save(buf,format='PNG',save_all=True,append_images=[Image.new('RGB',(20,20),'black')])
    assert upload(buf.getvalue()).status_code==422


def test_ocr_timeout_keeps_qr(monkeypatch):
    monkeypatch.setattr(images,'ocr_command',lambda:'tesseract')
    def timeout(*a,**kw):raise subprocess.TimeoutExpired('tesseract',15)
    monkeypatch.setattr(images.subprocess,'run',timeout)
    r=upload(image_bytes(qr_image('https://example.com/'))).json()
    assert r['ocr_status']=='timeout' and r['qr_status']=='decoded'


def test_ocr_failure_keeps_qr(monkeypatch):
    monkeypatch.setattr(images,'ocr_command',lambda:'tesseract')
    monkeypatch.setattr(images.subprocess,'run',lambda *a,**kw:subprocess.CompletedProcess([],1,b'',b'sensitive error'))
    r=upload(image_bytes(qr_image('https://example.com/'))).json()
    assert r['ocr_status']=='unavailable' and r['qr_status']=='decoded' and 'sensitive error' not in str(r)


def test_extraction_no_provider_or_persistence(monkeypatch,tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('GEMINI_API_KEY','fake')
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','fake')
    monkeypatch.setattr(integrations,'request',lambda *a,**kw:pytest.fail('Extraction must not contact cloud'))
    monkeypatch.setattr(images,'ocr_command',lambda:None)
    assert upload(image_bytes(qr_image('https://example.com/'))).status_code==200
    assert not list(tmp_path.iterdir())


def test_busy():
    assert images.SLOTS.acquire(False) and images.SLOTS.acquire(False)
    try: assert upload(b'fake').status_code==429
    finally: images.SLOTS.release();images.SLOTS.release()


def test_blank_image(monkeypatch):
    monkeypatch.setattr(images,'extract_text',lambda img:('', 'no_text',False))
    data=upload(image_bytes(Image.new('RGB',(100,100),'white'))).json()
    assert not data['text'] and not data['qr_codes']
    assert client.post('/api/scan',json={'text':'','mode':'screenshot'}).status_code==422
