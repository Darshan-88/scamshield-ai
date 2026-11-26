"""Initial accounts, sessions, scan metadata schema."""
from alembic import op
import sqlalchemy as sa
revision='0001_accounts'
down_revision=None
branch_labels=None
depends_on=None

def upgrade():
    op.create_table('users',sa.Column('id',sa.String(36),primary_key=True),sa.Column('email',sa.String(254),nullable=False,unique=True),sa.Column('password_hash',sa.String(255),nullable=False),sa.Column('created_at',sa.DateTime(timezone=True),nullable=False))
    op.create_table('login_sessions',sa.Column('id',sa.String(36),primary_key=True),sa.Column('user_id',sa.String(36),sa.ForeignKey('users.id',ondelete='CASCADE'),nullable=False),sa.Column('expires_at',sa.DateTime(timezone=True),nullable=False))
    op.create_index('ix_login_sessions_user_id','login_sessions',['user_id'])
    op.create_index('ix_login_sessions_expires_at','login_sessions',['expires_at'])
    op.create_table('scan_records',sa.Column('id',sa.String(36),primary_key=True),sa.Column('user_id',sa.String(36),sa.ForeignKey('users.id',ondelete='CASCADE'),nullable=False),sa.Column('mode',sa.String(16),nullable=False),sa.Column('score',sa.Integer(),nullable=False),sa.Column('level',sa.String(8),nullable=False),sa.Column('created_at',sa.DateTime(timezone=True),nullable=False),sa.CheckConstraint('score >= 0 AND score <= 100',name='ck_scan_score'),sa.CheckConstraint("level IN ('low','medium','high')",name='ck_scan_level'),sa.CheckConstraint("mode IN ('message','url','job','banking','screenshot')",name='ck_scan_mode'))
    op.create_index('ix_scan_user_time','scan_records',['user_id','created_at','id'])

def downgrade():
    op.drop_table('scan_records');op.drop_table('login_sessions');op.drop_table('users')
