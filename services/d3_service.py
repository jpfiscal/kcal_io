from flask import Flask, g, jsonify
from models import db, Kcal_in, Kcal_out, User_Weight
from sqlalchemy import func
from sqlalchemy.orm import aliased

def wtHistoryData(user_id):
    """Pull and prepare weight history data for the user's home screen's line graph"""
    wt_data = db.session.query(User_Weight.wt, User_Weight.wt_dt).filter_by(
        user_id=user_id
    ).order_by(User_Weight.wt_dt.asc()).all()
    wt_data_list = [{'wt': float(wt), 'wt_dt': wt_dt.strftime("%Y-%m-%d")} for wt, wt_dt in wt_data]
    return jsonify(wt_data_list)

def kcalSummaryData(user_id):
    """Pull and prepare KCAL IN vs. KCAL OUT history data for the user's home 
    screen's multi-bar graph"""

    KcalOutAlias = aliased(Kcal_out)
    KcalInAlias = aliased(Kcal_in)

    # Left join from Kcal_out to Kcal_in
    query1 = db.session.query(
        KcalOutAlias.activity_date.label('date'),
        func.sum(KcalOutAlias.kcal_out).label('total_kcal_out'),
        func.sum(KcalInAlias.kcal).label('total_kcal_in')
    ).outerjoin(
        KcalInAlias,
        KcalOutAlias.activity_date == KcalInAlias.meal_date
    ).filter(
        KcalOutAlias.user_id == user_id
    ).group_by(
        KcalOutAlias.activity_date
    )

    # Left join from Kcal_in to Kcal_out
    query2 = db.session.query(
        KcalInAlias.meal_date.label('date'),
        func.sum(KcalOutAlias.kcal_out).label('total_kcal_out'),
        func.sum(KcalInAlias.kcal).label('total_kcal_in')
    ).outerjoin(
        KcalOutAlias,
        KcalInAlias.meal_date == KcalOutAlias.activity_date
    ).filter(
        KcalInAlias.user_id == user_id
    ).group_by(
        KcalInAlias.meal_date
    )

    # Union the two queries
    kcal_data = query1.union(query2).order_by('date').all()

    kcal_data_list = [{
        'date': date.strftime("%Y-%m-%d"),
        'kcal_in': float(kcal) if kcal is not None else 0,
        'kcal_out': float(kcal_out) if kcal_out is not None else 0
    } for date, kcal_out, kcal in kcal_data]
    
    return jsonify(kcal_data_list)