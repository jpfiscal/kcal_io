"""updated kcal_out to add activity_date

Revision ID: 424dc51443e2
Revises: 2cd0b363cee8
Create Date: 2024-06-01 13:08:47.688741

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '424dc51443e2'
down_revision = '2cd0b363cee8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('kcal_out', schema=None) as batch_op:
        batch_op.add_column(sa.Column('activity_date', sa.DateTime(), nullable=False))
        batch_op.add_column(sa.Column('activity_nm', sa.Integer(), nullable=True))
        batch_op.drop_constraint('kcal_out_activity_id_fkey', type_='foreignkey')
        batch_op.create_foreign_key(None, 'activity', ['activity_nm'], ['id'])
        batch_op.drop_column('activity_id')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('kcal_out', schema=None) as batch_op:
        batch_op.add_column(sa.Column('activity_id', sa.INTEGER(), autoincrement=False, nullable=True))
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_foreign_key('kcal_out_activity_id_fkey', 'activity', ['activity_id'], ['id'])
        batch_op.drop_column('activity_nm')
        batch_op.drop_column('activity_date')

    # ### end Alembic commands ###
