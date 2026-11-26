"""Print reproducible metrics; no unsafe serialized model loading or dataset text in output."""
import argparse
import json
import os
from pathlib import Path
from backend.ml import get_model

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--dataset',type=Path);parser.add_argument('--report',type=Path,default=Path('model-report.json'));args=parser.parse_args()
    if args.dataset: os.environ['SMS_DATASET_PATH']=str(args.dataset.resolve())
    _,info=get_model(); args.report.write_text(json.dumps(info,indent=2)+'\n',encoding='utf-8'); print(json.dumps(info,indent=2))

if __name__=='__main__': main()
