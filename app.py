import os

from flask import Flask, render_template, request, flash, redirect, session, g, jsonify
from flask_debugtoolbar import DebugToolbarExtension
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
import base64
import hashlib
import requests
from datetime import datetime, timedelta

from forms import UserAddForm, LoginForm, UserDetailsForm, BodyWeightForm, ManualMealInputForm, MealPhotoForm, ManualActivityInputForm
from models import db, connect_db, User, User_Weight, FitBit, Kcal_in, Kcal_out, Activity

CURR_USER_KEY = "curr_user"

app = Flask(__name__)

if __name__ == "__main__":
    app.run(debug=True)

app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ.get('DATABASE_URL', 'postgresql:///kcalio'))

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False

migrate = Migrate(app,db)

app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY',"k4ch1_su1TMatchaW8CH")
app.config['DEBUG'] = True

toolbar = DebugToolbarExtension(app)

connect_db(app)

@app.before_request
def add_user_to_g():
    """If logged in, add curr user to Flask global"""

    if CURR_USER_KEY in session:
        g.user = db.session.get(User, session[CURR_USER_KEY])

    else:
        g.user = None

def do_login(user):
    session[CURR_USER_KEY] = user.id

def do_logout():
    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]

@app.route('/')
def homepage():
    """Show homepage
    
    - if logged in, show home dashboard screen
    - if not logged in, go to login screen
    """

    if g.user:
        today_kcal_out = Kcal_out.get_today_kcal_out_total(g.user.id)
        today_kcal_in = Kcal_in.get_today_kcal_in_total(g.user.id)
        return render_template(
            'home.html', 
            today_kcal_in = today_kcal_in, 
            today_kcal_out = today_kcal_out)
    else:
        return redirect('/login')
    
@app.route('/wtHistoryData')
def wtHistoryData():
    """Pull and prepare weight history data for the user's home screen's line graph"""
    user_id = g.user.id
    wt_data = db.session.query(User_Weight.wt, User_Weight.wt_dt).filter_by(
        user_id=user_id
    ).order_by(User_Weight.wt_dt.asc()).all()
    wt_data_list = [{'wt': float(wt), 'wt_dt': wt_dt.strftime("%Y-%m-%d")} for wt, wt_dt in wt_data]
    return jsonify(wt_data_list)

@app.route('/kcalSummaryData')
def kcalSummaryData():
    """Pull and prepare KCAL IN vs. KCAL OUT history data for the user's home 
    screen's multi-bar graph"""
    user_id = g.user.id
    kcal_data = db.session.query(Kcal_out.kcal_out,
                                Kcal_out.activity_date,
                                Kcal_in.kcal, 
                                Kcal_in.meal_date).join(Kcal_in).filter(
                                    Kcal_in.meal_date == Kcal_out.activity_date).filter_byA(
                                        user_id = user_id).order_by(Kcal_out.activity_date.asc()).all()

    print(f"kcal_data: {kcal_data}")
    kcal_data_list = [{'kcal_in': float(kcal),
                        'kcal_out': float(kcal_out),
                        'meal_dt': meal_dt.strftime("%Y-%m-%d"), 
                        'activity_dt' : activity_dt.strftime("%Y-%m-%d")} for kcal_out, activity_dt, kcal, meal_dt in kcal_data]
    
    print(f"kcal_data_list: {kcal_data_list}")
    return jsonify(kcal_data_list)

@app.route('/login', methods=['GET','POST'])
def login():
    """Handle user login"""

    form = LoginForm()

    if form.validate_on_submit():
        user = User.authenticate(form.username.data,
                                 form.password.data)
        
        if user:
            do_login(user)
            flash(f"Hello, {user.username}!", "success")
            return redirect("/")
        
        flash("Invalid Credentials.", "danger")
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET'])
def logout():
    """Handle log out of user"""

    do_logout()
    flash(f"You have been successfully logged out.", "success")
    return redirect('/login')

@app.route('/signup', methods=['GET','POST'])
def signup():
    """Allow new users to create an account"""
    print("Signup route hit")
    form = UserAddForm()
    print(f"submitted? {form.validate_on_submit()}")
    if form.validate() != True:
        print(f"Form errors: {form.errors}")
    if form.is_submitted and form.validate():
        print("Form submitted successfully")
        try:
            user = User.signup(
                username=form.username.data,
                email=form.email.data,
                password=form.password.data
                # ,password = form.password_retype.data
            )
            db.session.commit()

        # except IntegrityError:
        #     flash("Username or email is already being used by an existing account", 'danger')
        #     return render_template('signup.html', form=form)
        
        except IntegrityError as e:
            print(f"IntegrityError: {e}")
            db.session.rollback()
            flash("Username or email is already being used by an existing account", 'danger')
        except Exception as e:
            print(f"Unexpected error: {e}")
            db.session.rollback()  # Ensure rollback on any exception
            flash("An unexpected error occurred. Please try again.", 'danger')

        do_login(user)

        return redirect(f"/users/{user.id}/usersetup")
    
    else:
        if form.errors:
            print(f"Form errors: {form.errors}")
        return render_template('signup.html', form=form)

@app.route('/users/<int:user_id>', methods=['GET','POST'])
def viewUser(user_id):
    """View user details and option to update user details"""
    user = User.query.get(user_id)
    return render_template('user.html', user = user)

@app.route('/users/<int:user_id>/usersetup', methods=['GET','POST'])
def setup(user_id):
    """Users to set up a personal info"""
    user = User.query.get_or_404(user_id)
    form = UserDetailsForm()

    #pre-populate the form with existing user data and most recent weight data
    if (user.gender != None):
        latest_wt = User_Weight.query.filter_by(user_id=user_id).order_by(User_Weight.wt_dt.desc()).first()
        form.birthdate.data = user.birth_dt
        form.gender.data = user.gender
        form.weight.data = latest_wt.wt
        form.height.data = user.height
        form.fat_perc.data = latest_wt.fat_perc
    
    if form.is_submitted and form.validate():
        
        if user:
            user.birth_dt = form.birthdate.data
            user.gender = form.gender.data
            user.height = form.height.data

            user_weight = User_Weight(
                user_id = user.id,
                wt=form.weight.data,
                fat_perc = form.fat_perc.data,
                bmr = User_Weight.calculate_bmr(user.gender, form.weight.data, user.height, form.birthdate.data)
            )

            try:
                db.session.add(user_weight)
                db.session.commit()
                return redirect(f"/users/{g.user.id}/linkFitbit")
            except IntegrityError as e:
                db.session.rollback()
                flash("An error occurred while updating user details. Please try again", "danger")
                return redirect(f"/users/{user_id}/usersetup")
            
        else:
            flash("Invalid User", "danger")
            return redirect(f"/usersetup/{g.user.id}")
    else:
        return render_template('usersetup.html', form=form)
    
@app.route('/users/<int:user_id>/linkFitbit', methods=['GET','POST'])
def linkFitBit(user_id):
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
    print(f"url: {url}")
    return render_template('linkFitbit.html', user=user, url=url)

@app.route('/users/<int:user_id>/linkFitbit/callback', methods=['GET','POST'])
def linkFitBitCallback(user_id):
    """Obtain callback variables from Fitbit Auth URL"""
    user = User.query.get(user_id)
    client_id = "23RZYC"
    client_secret = "4bc7d9b86bed62e973998936393a6b37"
    code = request.args.get('code')
    state = request.args.get('state')

    if not code or not state:
        flash("Missing code or state from Fitbit authorization", "danger")
        return redirect("/users/<int:user_id>/linkFitbit", user_id = user_id)
    
    # Save the code and state to the database (assuming you have these fields in your FitBit model)
    fitbit_account = FitBit.query.filter_by(user_id=user_id).first()

    if fitbit_account:
        fitbit_account.auth_code = generate_auth_code(client_id, client_secret)
        fitbit_account.callback_code = code
        fitbit_account.state = state
    else:
        fitbit_account = FitBit(
            user_id = user_id,
            auth_code = generate_auth_code(client_id, client_secret),
            callback_code = code,
            state = state
        )
        db.session.add(fitbit_account)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred: {e}", "danger")

    # Request token and refresh token
    token_response = request_token(client_id, fitbit_account.auth_code, fitbit_account.callback_code, fitbit_account.pkce_code_verifier)
    print(token_response)
    
    # Check for errors in the response
    if "error" in token_response:
        flash(f"Error obtaining token: {token_response['error_description']}", "danger")
        return redirect('/users/<int:user_id>/linkFitbit', user_id=user_id)
    
    #store token details in database
    fitbit_account.token = token_response.get("access_token")
    fitbit_account.refresh_token = token_response.get("refresh_token")
    fitbit_account.expiry_dt = datetime.utcnow() + timedelta(seconds=token_response.get("expires_in"))
    fitbit_account.fitbit_user_id = token_response.get("user_id")

    try:
        db.session.commit()
        flash("Fitbit account linked and token obtained successfully", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred: {e}", "danger")

    return render_template('linkFitbit_callback.html', user=user, fitbit_account=fitbit_account)

def generate_auth_code(client_id, client_secret):
    auth_string = f"{client_id}:{client_secret}"
    auth_bytes = auth_string.encode('ascii')
    base64_bytes = base64.b64encode(auth_bytes)
    base64_string = base64_bytes.decode('ascii')
    return f"Basic {base64_string}"

def generate_code_verifier(length=128):
    """Generate cryptographic random string between 43 and 128 characters"""
    verifier = base64.urlsafe_b64encode(os.urandom(length)).rstrip(b'=').decode('ascii')
    return verifier

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

@app.route('/users/<int:user_id>/weight', methods=['GET','POST'])
def log_weight(user_id):
    """Allow user to view details about their weight history"""
    form = BodyWeightForm()
    user = User.query.get(user_id)

    if form.is_submitted and form.validate():
        weight = User_Weight.query.filter_by(user_id = user_id, wt_dt = form.weigh_in_date.data).first()
        
        # If the weight record for the selected date already exists then overwrite
        if weight:
            weight.wt = form.weight.data
            weight.fat_perc = form.fat_perc.data
            weight.bmr = User_Weight.calculate_bmr(user.gender, form.weight.data, user.height, user.birth_dt)
        #else create a new a new record for the selected date
        else:    
            weight = User_Weight(
                user_id = user_id,
                wt = form.weight.data,
                wt_dt = form.weigh_in_date.data,
                fat_perc = form.fat_perc.data,
                bmr = User_Weight.calculate_bmr(user.gender, form.weight.data, user.height, user.birth_dt)
            )
            db.session.add(weight)
        try:
            db.session.commit()
            flash("Weight logged", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {e}", "danger")
            return render_template('log_weight.html', form=form)
        return redirect("/")
    else:
        return render_template('logweight.html', form=form)

@app.route('/users/<int:user_id>/meals', methods=['GET','POST'])
def log_meal(user_id):
    man_form = ManualMealInputForm()
    pic_form = MealPhotoForm()
    if man_form.is_submitted and man_form.validate():
        meal = Kcal_in(
            user_id = user_id,
            meal_nm = man_form.meal_name.data,
            meal_lbl = man_form.meal_lbl.data,
            meal_date = man_form.meal_date.data,
            carb = man_form.carbs.data,
            protein = man_form.protein.data,
            fat = man_form.fat.data,
            kcal = man_form.total_kcal.data
        )
        db.session.add(meal)
        try:
            db.session.commit()
            flash("Meal logged", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {e}", "danger")
            return render_template('logmeal.html', man_form=man_form, pic_form = pic_form)
        return redirect("/")
    # elif pic_form.is_submitted and pic_form.validate():
    elif pic_form.is_submitted and pic_form.validate():
        try:
            db.session.commit()
            flash("Meal logged", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {e}", "danger")
            return render_template('logmeal.html', man_form=man_form, pic_form = pic_form)
        return redirect("/")
    else:
        return render_template('logmeal.html', man_form=man_form, pic_form=pic_form)
    
@app.route('/users/<int:user_id>/activity', methods=['GET','POST'])
def log_activity(user_id):
    form = ManualActivityInputForm()
    activities = Activity.query.with_entities(Activity.activity_nm).order_by(Activity.activity_nm).all()
    form.activity_nm.choices = [(activity.activity_nm, activity.activity_nm) for activity in activities]
    
    #checks to see whether bmr has been recorded for the day for the current user 
    auto_record = Kcal_out.query.filter(
        Kcal_out.is_auto == True,
        Kcal_out.user_id == user_id,
        Kcal_out.activity_date >= datetime.utcnow().date(),
        Kcal_out.activity_date < datetime.utcnow().date() + timedelta(days=1)
    ).first()
    
    if not auto_record:
        user_bmr = User_Weight.query.filter_by(
            user_id = user_id
        ).order_by(User_Weight.wt_dt.desc()).first().bmr

        auto_activity = Kcal_out(
            user_id=user_id,
            activity_id=None,  # Assuming this is optional or has a default
            activity_date=datetime.utcnow(),
            kcal_out=user_bmr,
            duration=None,  # Or any default value you prefer
            is_auto=True,
        )
        db.session.add(auto_activity)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {e}", "danger")
            return render_template('logactivity.html', form=form)

    if form.is_submitted and form.validate():
        activity = Kcal_out(
            user_id = user_id,
            activity_id = Activity.query.filter_by(activity_nm = form.activity_nm.data).first().id, #query for the id of the selected activity,
            activity_date = form.activity_date.data,
            kcal_out = form.kcal_out.data,
            duration = form.duration.data,
            is_auto = False,
        )
        db.session.add(activity)
        try:
            db.session.commit()
            flash("Meal logged", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {e}", "danger")
            return render_template('logactivity.html', form=form)
        return redirect("/")
    else:
        return render_template('logactivity.html', form=form)