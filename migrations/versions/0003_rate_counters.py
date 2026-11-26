"""Shared fixed-window request and provider counters."""
from alembic import op
import sqlalchemy as sa
revision = '0003_rate_counters'
down_revision = '0002_community'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('rate_counters', sa.Column('key', sa.String(64), primary_key=True), sa.Column('count',sa.Integer(),nullable=False),sa.Column('expires_at',sa.BigInteger(),nullable=False),sa.CheckConstraint('count > 0', name='ck_rate_positive'))
    op.create_index('ix_rate_counters_expires_at','rate_counters',['expires_at'])

def downgrade():
    op.drop_index('ix_rate_counters_expires_at',table_name='rate_counters')
    op.drop_table('rate_counters')
