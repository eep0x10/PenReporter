"""add body_text to evidences

Revision ID: 5a8cd2e7f901
Revises: 4f81ac5d3606
Create Date: 2026-02-27 18:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '5a8cd2e7f901'
down_revision = '4f81ac5d3606'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('evidences', sa.Column('body_text', sa.Text(), nullable=True))


def downgrade():
    op.drop_column('evidences', 'body_text')
