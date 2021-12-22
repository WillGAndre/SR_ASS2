"""blogposts features

Revision ID: 6c274b3dad62
Revises: e87a60f0d666
Create Date: 2021-12-21 10:41:37.318632

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6c274b3dad62'
down_revision = 'e87a60f0d666'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('blog_post', sa.Column('visibility', sa.String(length=10), nullable=True))
    op.add_column('blog_post', sa.Column('edited', sa.String(length=3), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('blog_post', 'edited')
    op.drop_column('blog_post', 'visibility')
    # ### end Alembic commands ###