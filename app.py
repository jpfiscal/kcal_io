import os

from flask import Flask, render_template, request, flash, redirect, session, g, jsonify
# from flask_debugtoolbar import DebugToolbarExtension
from flask_migrate import Migrate
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
from services.openAi_service import get_kcal_in_est
from services.op_service import do_login, do_logout
from services.fitbit_service import refresh_fitbit_token, get_fitbit_auto_kcal_out, genFitBitURL, FitBitCallback
from services.d3_service import wtHistoryData, kcalSummaryData
import json
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
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'upload_imgs')

# toolbar = DebugToolbarExtension(app)

connect_db(app)

@app.before_request
def add_user_to_g():
    """If logged in, add curr user to Flask global"""

    if CURR_USER_KEY in session:
        g.user = db.session.get(User, session[CURR_USER_KEY])

    else:
        g.user = None

@app.route('/')
def homepage():
    """Show homepage
    - if logged in, show home dashboard screen
    - if not logged in, go to login screen
    """

    if g.user:
        #display updated kcal in and out sums for the current day
        today_kcal_out = Kcal_out.get_today_kcal_out_total(g.user.id)
        today_kcal_in = Kcal_in.get_today_kcal_in_total(g.user.id)

        fitbit_account = FitBit.query.filter_by(user_id = g.user.id).first()
        if fitbit_account.token != None:
            #check and refresh fitbit token if it's close to expiry
            refresh_fitbit_token(g.user.id)
            #obtain fitbit's total kcal out data for the day
            get_fitbit_auto_kcal_out(g.user.id)

        return render_template(
            'home.html', 
            today_kcal_in = today_kcal_in, 
            today_kcal_out = today_kcal_out)
    else:
        return redirect('/login')
    
@app.route('/wtHistoryData')
def display_wtHistoryData():
    return wtHistoryData(g.user.id)

@app.route('/kcalSummaryData')
def display_kcalSummaryData():
    return kcalSummaryData(g.user.id)

@app.route('/login', methods=['GET','POST'])
def login():
    """Handle user login"""
    form = LoginForm()

    if form.validate_on_submit():
        user = User.authenticate(form.username.data,
                                 form.password.data)
        
        if user:
            do_login(user, CURR_USER_KEY)
            flash(f"Hello, {user.username}!", "success")
            return redirect("/")
        
        flash("Invalid Credentials.", "danger")
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET'])
def logout():
    """Handle log out of user"""
    do_logout(CURR_USER_KEY)
    flash(f"You have been successfully logged out.", "success")
    return redirect('/login')

@app.route('/signup', methods=['GET','POST'])
def signup():
    """Allow new users to create an account"""
    form = UserAddForm()
    
    if form.is_submitted and form.validate():
        try:
            user = User.signup(
                username=form.username.data,
                email=form.email.data,
                password=form.password.data
            )
            db.session.commit()
        
        except IntegrityError as e:
            db.session.rollback()
            flash("Username or email is already being used by an existing account", 'danger')
        except Exception as e:
            db.session.rollback()
            flash("An unexpected error occurred. Please try again.", 'danger')

        do_login(user, CURR_USER_KEY)
        return redirect(f"/users/{user.id}/usersetup")
    
    else:
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
        if not form.is_submitted():
            form.birthdate.data = user.birth_dt
            form.gender.data = user.gender
            form.weight.data = latest_wt.wt
            form.height.data = user.height
            form.fat_perc.data = latest_wt.fat_perc
    
    if form.validate_on_submit(): #form.is_submitted and form.validate():
        
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
            db.session.add(user_weight)
            try:
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
    user = User.query.get(user_id)
    url = genFitBitURL(user_id)
    return render_template('linkFitbit.html', user=user, url=url)


@app.route('/users/linkFitbit/callback', methods=['GET','POST'])
def linkFitBitCallback():
    """Obtain callback variables from Fitbit Auth URL"""
    user_id = g.user.id
    FitBitCallback(user_id, request)
    user = User.query.get(user_id)
    fitbit_account = FitBit.query.filter_by(user_id = user_id).first()
    return render_template('linkFitbit_callback.html', user=user, fitbit_account=fitbit_account)

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
        #Populate grid view at bottom of page
        wts = db.session.query(
            User_Weight.id,
            User_Weight.wt_dt,
            User_Weight.wt,
            User_Weight.fat_perc,
            User_Weight.bmr
        ).filter(
            User_Weight.user_id == user_id
        ).order_by(
            User_Weight.wt_dt.desc()
        ).limit(20).all()
        return render_template('logweight.html', form=form, wts=wts)

@app.route('/delete_wt/<int:wt_id>', methods=['POST'])
def delete_wt(wt_id):
    """delete selected meal entry by their id"""
    wt = User_Weight.query.get_or_404(wt_id)
    db.session.delete(wt)
    try:
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}) 

@app.route('/users/<int:user_id>/meals', methods=['GET','POST'])
def log_meal(user_id):
    man_form = ManualMealInputForm()
    pic_form = MealPhotoForm()

    # IF REQUEST IS SUBMITTED FROM THE MANUAL UPLOAD FORM
    if request.form.get('form_type') == 'manual' and man_form.is_submitted and man_form.validate():
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
    
    # IF REQUEST IS SUBMITTED FROM PHOTO UPLOAD FORM
    elif request.form.get('form_type') == 'photo' and pic_form.is_submitted and pic_form.validate():
        f = pic_form.meal_photo.data
        if f:
            filename = secure_filename(f.filename)
            unique_filename = str(datetime.utcnow().timestamp()) + "_" + filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            f.save(filepath)
            #call function that uses ChatGPT API to recognize food in uploaded photo
            kcal_in_est = get_kcal_in_est(filepath)
            if kcal_in_est == "No food was recognized from the image you provided.":
                flash(kcal_in_est,"danger")
                #delete the file that was uploaded
                os.remove(filepath)
            else:
                #Save record to kcal_in including filename
                try:
                    kcal_in_est_json = json.loads(kcal_in_est)
                    meal = Kcal_in(
                        user_id = user_id,
                        meal_nm = kcal_in_est_json["name"],
                        meal_lbl = pic_form.meal_lbl.data,
                        meal_date = pic_form.meal_date.data,
                        carb = kcal_in_est_json["carbs"],
                        protein = kcal_in_est_json["protein"],
                        fat = kcal_in_est_json["fat"],
                        kcal = kcal_in_est_json["calories"],
                        ref_filename = unique_filename
                    )
                    db.session.add(meal)
                    try:
                        db.session.commit()
                        flash(f"\"{kcal_in_est_json['name']}\" logged", "success")
                    except Exception as e:
                        db.session.rollback()
                        flash(f"An error occurred: {e}", "danger")
                        return render_template('logmeal.html', man_form=man_form, pic_form = pic_form)
                    return redirect(f"/users/{user_id}/meals")
                except json.JSONDecodeError:
                    flash("Failed to parse response from API", "danger")
                    os.remove(filepath)
                    return render_template('logmeal.html', man_form = man_form, pic_form = pic_form)
        return redirect("/")
    else:
        #populate grid view at bottom of page
        meals = db.session.query(
            Kcal_in.id,
            Kcal_in.meal_date,
            Kcal_in.meal_lbl,
            Kcal_in.meal_nm,
            Kcal_in.kcal
        ).filter(
            Kcal_in.user_id == user_id
        ).order_by(
            Kcal_in.meal_date.desc()
        ).limit(20).all()
        return render_template('logmeal.html', man_form=man_form, pic_form=pic_form, meal_list = meals)

@app.route('/delete_meal/<int:meal_id>', methods=['POST'])
def delete_meal(meal_id):
    """delete selected meal entry by their id"""
    meal = Kcal_in.query.get_or_404(meal_id)
    db.session.delete(meal)
    try:
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/users/<int:user_id>/activity', methods=['GET','POST'])
def log_activity(user_id):
    form = ManualActivityInputForm()
    activities = Activity.query.with_entities(Activity.activity_nm).order_by(Activity.activity_nm).all()
    form.activity_nm.choices = [(activity.activity_nm, activity.activity_nm) for activity in activities]
    
    #If the user is linked to a Fitbit account, create a flash messages warning users that FitBit is already providing 
    #calorie expenditure data and anything added here would be in addition to what FitBit captures
    fitbit_account = FitBit.query.filter_by(user_id = user_id).first()

    if fitbit_account.fitbit_user_id != None:
        flash('Your account is linked to a FitBit account which is already providing calorie expenditure data. Anything logged here will be in addition to what FitBit is able to capture.','warning')

    #checks to see whether bmr has been recorded for the day for the current user 
    auto_record = Kcal_out.query.filter(
        Kcal_out.is_auto == True,
        Kcal_out.user_id == user_id,
        Kcal_out.activity_date >= datetime.utcnow().date(),
        Kcal_out.activity_date < datetime.utcnow().date() + timedelta(days=1)
    ).first()
    
    if not auto_record:
        user_wt = User_Weight.query.filter_by(
            user_id = user_id
        ).order_by(User_Weight.wt_dt.desc()).first()

        if (user_wt):
            user_bmr = user_wt.bmr

            auto_activity = Kcal_out(
                user_id=user_id,
                activity_id=Activity.query.filter(Activity.activity_nm == 'BMR').first().id, 
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
        activities = db.session.query(
            Kcal_out.id,
            Kcal_out.activity_date,
            Kcal_out.kcal_out,
            Activity.activity_nm,
            Kcal_out.is_auto
        ).outerjoin(Activity,Kcal_out.activity_id == Activity.id).filter(
            Kcal_out.user_id == user_id
        ).order_by(
            Kcal_out.activity_date.desc()
        ).limit(20).all()
        return render_template('logactivity.html', form=form, activities = activities)
    
@app.route('/delete_activity/<int:activity_id>', methods=['POST'])
def delete_activity(activity_id):
    """delete selected activity entry by their id"""
    meal = Kcal_out.query.get_or_404(activity_id)
    db.session.delete(meal)

    try:
        db.session.commit()
        flash("successfully deleted activity", "success")
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        flash(f"Error occurred while attempting to delete actvity", "danger")
        return jsonify({'success': False, 'error': str(e)})