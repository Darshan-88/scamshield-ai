"""Community reporting and operator-granted admin permissions."""
from alembic import op
import sqlalchemy as sa
revision='0002_community'
down_revision='0001_accounts'
branch_labels=None
depends_on=None

def upgrade():
    op.add_column('users', sa.Column('is_admin',sa.Boolean(),nullable=False,server_default=sa.false()))
    op.create_table('community_reports',
        sa.Column('id',sa.String(36),primary_key=True),
        sa.Column('user_id',sa.String(36),sa.ForeignKey('users.id',ondelete='CASCADE'),nullable=False),
        sa.Column('category',sa.String(24),nullable=False),sa.Column('tactic',sa.String(32),nullable=False),
        sa.Column('domain',sa.String(253),nullable=False),sa.Column('status',sa.String(12),nullable=False),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('reviewed_at',sa.DateTime(timezone=True)),
        sa.Column('reviewer_id',sa.String(36),sa.ForeignKey('users.id',ondelete='SET NULL')),
        sa.Column('review_reason',sa.String(32)),sa.Column('revision',sa.Integer(),nullable=False),
        sa.UniqueConstraint('user_id','category','tactic','domain',name='uq_report_indicator_owner'),
        sa.CheckConstraint("status IN ('pending','verified','rejected')",name='ck_report_status'))
    op.create_index('ix_report_public','community_reports',['status','category','tactic','domain'])
    op.create_index('ix_report_owner_time','community_reports',['user_id','created_at','id'])
    op.create_index('ix_report_review_queue','community_reports',['status','created_at','id'])

def downgrade():
    op.drop_table('community_reports')
    op.drop_column("users", "is_admin")
