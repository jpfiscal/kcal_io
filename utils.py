from flask import Flask, jsonify, flash
from models import db, Kcal_out


def rm_activity(activity_id):
    meal = Kcal_out.query.get_or_404(activity_id)
    db.session.delete(meal)

    try:
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        return e