"""Trusted operator CLI; never exposed as an HTTP endpoint."""
import argparse
from .db import SessionLocal, User

def main():
    parser=argparse.ArgumentParser(description='Grant or revoke moderator access by exact account UUID. Verify account ownership out of band.')
    parser.add_argument('action',choices=['grant','revoke']);parser.add_argument('user_id')
    args=parser.parse_args()
    with SessionLocal() as db:
        user=db.get(User,args.user_id)
        if not user: parser.error('Account UUID not found.')
        user.is_admin=args.action=='grant';db.commit()
    print('Moderator access '+('granted' if args.action=='grant' else 'revoked')+'.')

if __name__=='__main__': main()
