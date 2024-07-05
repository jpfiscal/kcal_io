from flask import Flask, g, flash
from sqlalchemy.exc import IntegrityError
from models import db, FitBit, Kcal_out, User
from datetime import datetime, timedelta

import base64
import os
import hashlib
import requests

def refresh_fitbit_token(user_id):
    #check user's token is within 2 hours of being expired..if so, refresh token and update fitbit_account record
    token_expiry = FitBit.query.filter_by(user_id = g.user.id).first().expiry_dt
        
    if(datetime.utcnow() >= (token_expiry - timedelta(hours=2))):
        FitBit.get_refresh_token(g.user.id)

def get_fitbit_auto_kcal_out(user_id):
    #check to see if any auto kcal_out records have been recorded for th+
    # e current day
        #ONLY IF the current user has an active fitbit user account linked to their kcalio account
    fitbit_account = FitBit.query.filter_by(user_id = user_id).first()

    if fitbit_account:
        kcal_out_auto = Kcal_out.query.filter(
            Kcal_out.user_id == g.user.id,
            Kcal_out.activity_date >= datetime.utcnow().date(),
            Kcal_out.activity_date < datetime.utcnow().date() + timedelta(days=1),
            Kcal_out.is_auto == True
        ).first()

        #if there is an "auto" record in the db for the current user and date,
        #then update the existing auto record with the updated kcal_out data from Fitbit
        activity_data = FitBit.get_user_activity(user_id, datetime.utcnow().date().strftime("%Y-%m-%d"))
        if kcal_out_auto:
            kcal_out_auto.kcal_out = activity_data['summary']['caloriesOut']
        #if there is not already an "auto" record in the db for the current user and date,
        #then write a new record with today's current reading on fitbit calories out
        else:
            activity_data = FitBit.get_user_activity(g.user.id, datetime.utcnow().date().strftime("%Y-%m-%d"))
            kcal_out_bmr = Kcal_out(
                user_id = g.user.id,
                activity_date = datetime.utcnow().date(),
                kcal_out = activity_data['summary']['caloriesOut'],
                is_auto = True
            )
            db.session.add(kcal_out_bmr)
        try:
            db.session.commit()
        except IntegrityError as e:
            db.session.rollback()
            flash("An error occurred while updating kcal out records. Please try again", "danger")

def generate_code_verifier(length=128):
    """Generate cryptographic random string between 43 and 128 characters"""
    verifier = base64.urlsafe_b64encode(os.urandom(length)).rstrip(b'=').decode('ascii')
    return verifier
#brought over from app.py just above "generate_code_challenge"

def generate_code_challenge(verfier):
    """Generate a code challenge from the code verifier"""
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verfier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')
    return challenge

def request_token(client_id, auth_code, callback_code, code_verifier):
    url = "https://api.fitbit.com/oauth2/token"
    headers = {
        "Authorization": auth_code,
        "Content-Type": 'application/x-www-form-urlencoded'
    }
    data = {
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": callback_code,
        "code_verifier": code_verifier
    }
    response = requests.post(url, headers=headers, data=data)
    return response.json()

def genFitBitURL(user_id):
    """Give users the option to link their FitBit account"""
    user = User.query.get(user_id)
    client_id = '23RZYC'
    # client_secret = '4bc7d9b86bed62e973998936393a6b37'
    code_verifier = generate_code_verifier(43)
    code_challenge = generate_code_challenge(code_verifier)
    state = generate_code_verifier(32)

    fitbit_account = FitBit.query.filter_by(user_id=user_id).first()

    #save generated codes to db
    if fitbit_account:
        url = f"https://www.fitbit.com/oauth2/authorize?response_type=code&client_id={client_id}&scope=activity+cardio_fitness+electrocardiogram+heartrate+location+nutrition+oxygen_saturation+profile+respiratory_rate+settings+sleep+social+temperature+weight&code_challenge={fitbit_account.pkce_code_challenge}&code_challenge_method=S256&state={fitbit_account.state}"
    else:
        fitbit_account = FitBit(
            user_id = user_id,
            pkce_code_verifier = code_verifier,
            pkce_code_challenge = code_challenge,
            state = state
        )
        db.session.add(fitbit_account)
        try:
            db.session.commit()
            flash("Fitbit account linked successfully", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {e}", "danger")
        url = f"https://www.fitbit.com/oauth2/authorize?response_type=code&client_id={client_id}&scope=activity+cardio_fitness+electrocardiogram+heartrate+location+nutrition+oxygen_saturation+profile+respiratory_rate+settings+sleep+social+temperature+weight&code_challenge={code_challenge}&code_challenge_method=S256&state={state}"
    
    return url
    # return render_template('linkFitbit.html', user=user, url=url)