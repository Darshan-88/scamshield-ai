from fastapi.testclient import TestClient
from backend.main import app
client=TestClient(app)
def test_home():
    assert 'ScamShield' in client.get('/').text

def test_health():
    assert client.get('/api/health').json()['status']=='ok'

def test_high():
    r=client.post('/api/scan',json={'text':'Account blocked. Share your OTP immediately and pay processing fee.'}).json()
    assert r['level']=='high' and r['score']==90

def test_normal():
    assert client.post('/api/scan',json={'text':'Meeting at noon tomorrow.'}).json()['score']==0

def test_url():
    r=client.post('/api/scan',json={'text':'http://192.0.2.1/login','mode':'url'}).json()
    assert r['score']==35

def test_invalid():
    for data in [{'text':' '},{'text':'invalid','mode':'url'},{'text':'hello','mode':'other'}]:
        assert client.post('/api/scan',json=data).status_code==422

def test_model_metadata():
    data=client.get('/api/model').json()
    assert data['training_samples']>=100
    assert 0<=data['f1']<=1
    assert sum(map(sum,data['confusion_matrix']))==data['samples']
    assert 'evaluation' in data

def test_hybrid_ml_and_rules():
    r=client.post('/api/scan',json={'text':'Earn thousands per day liking videos; deposit funds to join our team.'}).json()
    assert r['engine']=='hybrid-v7'
    assert 0<=r['ml']['spam_score']<=100
    assert r['score']==max(r['rule_score'],r['ml_contribution'])
    assert r['score']>=r['rule_score']
    assert r['ml']['label'] in ('spam-like','ham-like')

def test_url_skips_text_model():
    r=client.post('/api/scan',json={'text':'https://example.com','mode':'url'}).json()
    assert r['ml'] is None and r['ml_contribution']==0
    assert r['score']==r['rule_score']

def test_prediction_not_fraud_probability():
    r=client.post('/api/scan',json={'text':'Your interview has been scheduled tomorrow.'}).json()
    assert 'not a fraud probability' in r['disclaimer']
    assert 'not a fraud probability' in r['ml']['note']
