from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from decimal import Decimal

from datetime import datetime

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

# class Goal_Weight(db.Model):
#     """Stores historical weight of a user"""
#     __tablename__ = 'goal_wt'

#     id = db.Column(
#         db.Integer,
#         primary_key=True
#     )

#     user_id = db.Column(
#         db.Integer,
#         db.ForeignKey('users.id', ondelete='cascade')
#     )

#     goal_wt = db.Column(
#         db.Numeric(4,2),
#         nullable = False
#     )

#     goal_fat_perc = db.Column(
#         db.Numeric(3,2),
#         nullable = True
#     )

#     goal_set_dt = db.Column(
#         db.DateTime,
#         nullable=True,
#         default = datetime.utcnow()
#     )

#     goal_dt = db.Column(
#         db.DateTime,
#         nullable=True
#     )

#     create_dt = db.Column(
#         db.DateTime,
#         nullable=False,
#         default=datetime.utcnow()
#     )

#     updated_at = db.Column(
#         db.DateTime,
#         nullable=True,
#         onupdate=datetime.utcnow()
#     )

#     goals = db.relationship('User')

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

    meal_time = db.Column(
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

    activity_id = db.Column(
        db.Integer,
        db.ForeignKey('activity.id')
    )

    kcal_out = db.Column(
        db.Numeric(6,2),
        nullable=False
    )

    duration = db.Column(
        db.Numeric(6,2),
        nullable=False
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