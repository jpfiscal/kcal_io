from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from decimal import Decimal
from datetime import datetime, timedelta
from utils import generate_auth_code

import requests

bcrypt = Bcrypt()
db = SQLAlchemy()

class User(db.Model):
    """Connection of a follower <-> followed_user."""

    __tablename__ = 'users'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    email = db.Column(
        db.Text,
        nullable=False,
        unique=True
    )

    username = db.Column(
        db.Text,
        nullable=False,
        unique=True,
    )

    password = db.Column(
        db.Text,
        nullable=False,
    )

    birth_dt = db.Column(
        db.Date,
        nullable=True
    )

    gender = db.Column(
        db.Text,
        nullable = True
    )

    height = db.Column(
        db.Numeric(5,2),
        nullable = True
    )

    # pref_ht_metric = db.Column(
    #     db.Text,
    #     nullable = False
    # )

    # pref_wt_metric = db.Column(
    #     db.Text,
    #     nullable = False
    # )

    create_dt = db.Column(
        db.DateTime,
        nullable=True,
        default=datetime.utcnow()
    )

    update_dt = db.Column(
        db.DateTime,
        nullable=True,
        onupdate=datetime.utcnow()
    )

    @classmethod
    def signup(cls, username, email, password):
        """Create new user account.
        Hashes password and asdds user to db."""

        hashed_pwd = bcrypt.generate_password_hash(password).decode('UTF-8')

        user = User(
            username=username,
            email=email,
            password=hashed_pwd
        )
        db.session.add(user)
        return user
    
    @classmethod
    def authenticate(cls, username, password):
        """Find user with `username` and `password`."""

        user = cls.query.filter_by(username=username).first()

        if user:
            is_auth = bcrypt.check_password_hash(user.password, password)
            if is_auth:
                return user

        return False

class User_Weight(db.Model):
    """Stores historical weight of a user"""
    __tablename__ = 'user_wt'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='cascade')
    )

    wt = db.Column(
        db.Numeric(6,2),
        nullable = False
    )

    wt_dt = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow()
    )

    fat_perc = db.Column(
        db.Numeric(5,2),
        nullable = True
    )

    bmr = db.Column(
        db.Numeric(9,2),
        nullable = False
    )

    create_dt = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow()
    )

    update_dt = db.Column(
        db.DateTime,
        nullable=True,
        onupdate=datetime.utcnow()
    )

    weighs = db.relationship('User')

    @staticmethod
    def calculate_bmr(gender, weight, height, birth_date):
        """Calculate BMR based on user details. Replace this with your actual BMR calculation logic."""
        # convert decimal to float
        weight = float(weight) if isinstance(weight, Decimal) else weight
        height = float(height) if isinstance(height, Decimal) else height
        # Example calculation (Mifflin-St Jeor Equation)
        age = (datetime.now().date() - birth_date).days // 365
        if gender == 'M':
            return 10 * weight + 6.25 * height - 5 * age + 5
        elif gender == 'F':
            return 10 * weight + 6.25 * height - 5 * age - 161
        return 0

class FitBit(db.Model):
    """Stores users FitBit Account Details"""
    __tablename__ = 'fitbit_account'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='cascade')
    )

    pkce_code_verifier = db.Column(
        db.String,
        nullable = True
    )

    pkce_code_challenge = db.Column(
        db.String,
        nullable = True
    )

    auth_code = db.Column(
        db.String,
        nullable=True
    )

    callback_code = db.Column(
        db.String,
        nullable=True
    )

    state = db.Column(
        db.String,
        nullable=False
    )

    fitbit_user_id = db.Column(
        db.Text,
        nullable=True
    )

    token = db.Column(
        db.Text,
        nullable=True
    )

    refresh_token = db.Column(
        db.Text,
        nullable=True
    )

    expiry_dt = db.Column(
        db.DateTime,
        nullable=True
    )

    create_dt = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow()
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=True,
        onupdate=datetime.utcnow()
    )

    fitbits = db.relationship('User')

    @staticmethod
    def get_refresh_token(user_id):
        client_id = "23RZYC"
        client_secret = "4bc7d9b86bed62e973998936393a6b37"
        fitbit_account = FitBit.query.filter_by(user_id = user_id).first()
        url = "https://api.fitbit.com/oauth2/token"
        headers = {
            "Authorization": generate_auth_code(client_id=client_id, client_secret=client_secret),
            "Content-Type": "application/x-www-form-urlencoded"
        }
        print(f"auth code: {generate_auth_code(client_id=client_id, client_secret=client_secret)}")
        print(f"current refresh token: {fitbit_account.refresh_token}")
        data = {
            "grant_type":"refresh_token",
            "client_id": client_id,
            "refresh_token": fitbit_account.refresh_token
        }
        response = requests.post(url, headers=headers, data=data).json()
        print(f"response: {response}")
        
        if 'access_token' in response:
            fitbit_account.token = response['access_token']
            fitbit_account.refresh_token = response['refresh_token']
            fitbit_account.expiry_dt = datetime.utcnow() + timedelta(seconds = response['expires_in'])
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()

        return response

    @staticmethod
    def get_user_activity(user_id, date):
        fitbit_account = FitBit.query.filter_by(user_id = user_id).first()
        url = f"https://api.fitbit.com/1/user/-/activities/date/{date}.json"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {fitbit_account.token}"
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            return data
        else:
            return None

class Kcal_in(db.Model):
    """Records all meals or Calories that the users put INto their body"""
    __tablename__ = 'kcal_in'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='cascade')
    )

    meal_nm = db.Column(
        db.Text,
        nullable=False
    )

    meal_lbl = db.Column(
        db.Text,
        nullable=False
    )

    meal_date = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow()
    )

    meal_wt = db.Column(
        db.Numeric(5,2),
        nullable=True
    )

    carb = db.Column(
        db.Numeric(5,2),
        nullable=True
    )

    protein = db.Column(
        db.Numeric(5,2),
        nullable=True
    )

    fat = db.Column(
        db.Numeric(5,2),
        nullable=True
    )

    kcal = db.Column(
        db.Numeric(5,2),
        nullable=False
    )

    ref_filename = db.Column(
        db.Text,
        nullable = True
    )

    create_dt = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow()
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=True,
        onupdate=datetime.utcnow()
    )

    eats = db.relationship('User')

    @staticmethod
    def get_today_kcal_in_total(user_id):
        today = datetime.utcnow().date()

        total_kcal_in = db.session.query(func.sum(Kcal_in.kcal)).filter(
            Kcal_in.user_id == user_id,
            Kcal_in.meal_date >= today,
            Kcal_in.meal_date < today + timedelta(days=1)
        ).scalar()
        return total_kcal_in or 0


class Kcal_out(db.Model):
    """Records all activies or Calories that the users burnt OUT of their body"""
    __tablename__ = 'kcal_out'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete='cascade')
    )

    activity_date = db.Column(
        db.DateTime,
        nullable = False,
        default=datetime.utcnow()
    )

    activity_id = db.Column(
        db.Integer,
        db.ForeignKey('activity.id')
    )

    kcal_out = db.Column(
        db.Numeric(7,2),
        nullable=False
    )

    duration = db.Column(
        db.Numeric(6,2),
        nullable=True
    )

    is_auto = db.Column(
        db.Boolean,
        nullable=False
    )

    create_dt = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow()
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=True,
        onupdate=datetime.utcnow()
    )

    burns = db.relationship('User')
    activity = db.relationship('Activity')

    @staticmethod
    def get_today_kcal_out_total(user_id):
        today = datetime.utcnow().date()

        total_kcal_out = db.session.query(func.sum(Kcal_out.kcal_out)).filter(
            Kcal_out.user_id == user_id,
            Kcal_out.activity_date >= today,
            Kcal_out.activity_date < today + timedelta(days=1)
        ).scalar()

        return total_kcal_out or 0

class Activity(db.Model):
    """Reference table of all activities in the system"""
    __tablename__ = 'activity'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    activity_nm = db.Column(
        db.Text,
        nullable=False
    )

def connect_db(app):
    db.app = app
    db.init_app(app)