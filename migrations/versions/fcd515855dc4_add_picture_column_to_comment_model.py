"""Add picture column to Comment model

Revision ID: fcd515855dc4
Revises: 982c98681fef
Create Date: 2024-09-10 20:34:26.428017

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fcd515855dc4'
down_revision = '982c98681fef'
branch_labels = None
depends_on = None


def upgrade():
    # Add a new column to the 'comment' table
    op.add_column('comment', sa.Column('picture', sa.String(length=150), nullable=True))

def downgrade():
    # Remove the column if rolling back
    op.drop_column('comment', 'picture')

    # ### end Alembic commands ###
