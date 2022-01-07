"""rm unique roles

Revision ID: 16a18e095ad0
Revises: 2cdc6a79f782
Create Date: 2022-01-07 14:50:49.996626

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '16a18e095ad0'
down_revision = '2cdc6a79f782'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('ix_user_role', table_name='user')
    op.create_index(op.f('ix_user_role'), 'user', ['role'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_user_role'), table_name='user')
    op.create_index('ix_user_role', 'user', ['role'], unique=False)
    # ### end Alembic commands ###
