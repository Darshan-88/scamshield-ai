"""Local TF-IDF + logistic regression classifier. No network at inference."""
from pathlib import Path
import json
import os
import hashlib
import re
from functools import lru_cache
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split

DATA = Path(__file__).resolve().parents[1] / 'data'

def load_rows(path):
    if Path(path).stat().st_size > 20*1024*1024: raise ValueError('Dataset exceeds 20 MiB')
    rows = {}
    for line in Path(path).read_text(encoding='utf-8-sig', errors='strict').splitlines():
        label, sep, message = line.partition('\t')
        if not sep or label not in {'ham','spam'} or not message.strip():
            continue
        key = re.sub(r'\s+', ' ', message.strip().casefold())
        if key in rows and rows[key][1] != label:
            raise ValueError('Conflicting labels in dataset')
        rows[key] = (message.strip(), label)
    return list(rows.values())

def build_model():
    return Pipeline([('features', FeatureUnion([
        ('word', TfidfVectorizer(ngram_range=(1,2), sublinear_tf=True, max_features=30000)),
        ('char', TfidfVectorizer(analyzer='char_wb', ngram_range=(3,5), sublinear_tf=True, max_features=40000)),
    ])), ('classifier', LogisticRegression(C=5, max_iter=1000, class_weight='balanced', random_state=42))])

def fit(rows):
    x,y=zip(*rows)
    return build_model().fit(x,y)

def evaluate(model, rows):
    x,y=zip(*rows); pred=model.predict(x)
    return {'samples':len(y),'accuracy':float(accuracy_score(y,pred)), 'precision':float(precision_score(y,pred,pos_label='spam',zero_division=0)), 'recall':float(recall_score(y,pred,pos_label='spam',zero_division=0)), 'f1':float(f1_score(y,pred,pos_label='spam',zero_division=0)), 'confusion_matrix':confusion_matrix(y,pred,labels=['ham','spam']).tolist()}

@lru_cache(maxsize=1)
def get_model():
    # Train once per process from readable local data; avoids unsafe pickle loading.
    starter = load_rows(DATA/'starter.tsv')
    external = Path(os.environ.get('SMS_DATASET_PATH') or DATA/'SMSSpamCollection')
    if os.getenv('SMS_DATASET_PATH') and not external.is_file(): raise ValueError('Configured SMS dataset is missing')
    if external.exists():
        rows = load_rows(external)
        if len(rows)<100 or min(sum(y==label for _,y in rows) for label in ('ham','spam'))<10:
            raise ValueError('External SMS dataset is invalid or incomplete')
        train,test=train_test_split(rows,test_size=.2,stratify=[y for _,y in rows],random_state=42)
        # Keep public holdout separate from the bundled synthetic augmentation.
        held={re.sub(r'\s+',' ',x.strip().casefold()) for x,_ in test}
        train += [r for r in starter if re.sub(r'\s+',' ',r[0].strip().casefold()) not in held]
        model=fit(train)
        info={'real_dataset':True,'dataset_sha256':hashlib.sha256(external.read_bytes()).hexdigest(),'split_seed':42,'dataset':'External SMS dataset + synthetic examples','evaluation':'deduplicated public SMS holdout; near duplicates may remain','training_samples':len(train),**evaluate(model,test)}
    else:
        model=fit(starter)
        info={'real_dataset':False,'dataset':'Bundled synthetic starter examples','evaluation':'synthetic smoke test only; not real-world validation','training_samples':len(starter),**evaluate(model,load_rows(DATA/'demo_eval.tsv'))}
    return model,info

def predict(text):
    model,_=get_model()
    p=float(model.predict_proba([text])[0][list(model.classes_).index('spam')])
    return {'spam_score':round(p*100,1),'label':'spam-like' if p>=.5 else 'ham-like','note':'Uncalibrated text-classifier output, not a fraud probability.'}

if __name__=='__main__':
    print(json.dumps(get_model()[1],indent=2))
