from csv import DictReader
from models import Activity
from app import db,app

with app.app_context():
    db.drop_all()
    db.create_all()

    with open('generator/activities.csv') as activities:
        data = list(DictReader(activities))
        db.session.bulk_insert_mappings(Activity, data)
        db.session.commit()