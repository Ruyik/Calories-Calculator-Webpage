from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from itsdangerous import URLSafeTimedSerializer, BadSignature,  SignatureExpired
import os
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://databaserender_user:b50MsFDpIAV9YawXGi5GNVIOMOIPgkn1@dpg-clnq8c3j65ls7389gr8g-a.singapore-postgres.render.com/databaserender'
#postgres://databaserender_user:b50MsFDpIAV9YawXGi5GNVIOMOIPgkn1@dpg-clnq8c3j65ls7389gr8g-a.singapore-postgres.render.com/databaserender
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'the random string NRY'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ruyik1207@gmail.com'
app.config['MAIL_PASSWORD'] = 'qfts rzvu kupf dizk'
db = SQLAlchemy(app)
migrate= Migrate(app, db)
mail = Mail(app)


def get_reset_token(self, expires_sec=1800):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'], expires_sec)
    return s.dumps({'user_id': self.id}).decode('utf-8')


@staticmethod
def verify_reset_token(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        user_id = s.loads(token)['user_id']
    except:
        return None
    return User.query.get(user_id)

def generate_reset_token(user):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    reset_token = serializer.dumps({'user_id': user.id}, salt='reset-password')

    # For debugging purposes, print the generated reset token
    print("Generated Reset Token:", reset_token)

    return reset_token


def validate_reset_token(token):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        # Extract the user_id from the token
        user_id = serializer.loads(token, salt='reset-password', max_age=3600)['user_id']

        # Query the user by user_id directly
        user = User.query.get(user_id)

        return user
    except SignatureExpired as e:
        print("Token has expired:", e)
        return None
    except BadSignature as e:
        print("Bad signature:", e)
        return None


def send_reset_email(user):
    token = user.reset_token
    msg = Message('Password Reset Request', sender='ruyik1207@gmail.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link: 
    {url_for('reset_password', token=token, _external=True)}
    '''
    mail.send(msg)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    reset_token = db.Column(db.String(200), nullable=True)


class FoodInformation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    food = db.Column(db.String(200), nullable=False)
    calories = db.Column(db.Float, nullable=False)


class UserCalories(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    food = db.Column(db.String(200), nullable=False)
    consumed_calories = db.Column(db.Float, nullable=False)
    remaining_calories = db.Column(db.Float, nullable=False)


def before_first_request():
    with app.app_context():
        db.create_all()
        UserCalories.query.delete()
        db.session.commit()


def import_data(excel_file):
    # Read data from the Excel file with 'openpyxl' engine
    df = pd.read_excel(excel_file, engine='openpyxl')

    # Iterate through the data and insert it into the database
    for index, row in df.iterrows():
        food = row['food']
        calories = row['calories']

        # Check if the food entry already exists in the database
        existing_food = FoodInformation.query.filter_by(food=food).first()

        if existing_food is None:
            new_entry = FoodInformation(food=food, calories=calories)
            db.session.add(new_entry)
        else:
            existing_food.calories = calories

    db.session.commit()


with app.app_context():
    # Call the import_data method here
    import_data('FoodCalories.xlsx')


@app.route('/')
def index():
    return render_template('main.html')


@app.route('/process_form', methods=['POST'])
def process_form():
    action = request.form.get('action')
    if action == 'register':
        return render_template('register.html')
    else:
        return render_template('login.html')


@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        # Handle the case where the email already exists
        return render_template('error.html',
                               message='Email already registered. Please log in or choose a different email.')
    else:
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
    # Proceed with user registration
    return render_template('input_calories.html', username=username)


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['username'] = user.username

        # Set success message
        success_message = 'Login successful. Welcome back, {}!'.format(username)
        flash(success_message, 'success')

        return render_template('input_calories.html', username=username)
    else:

        return render_template('login_fail.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        if email:
            user = User.query.filter_by(email=email).first()

            if user:
                # Generate a unique token for the password reset link
                reset_token = generate_reset_token(user)

                reset_token = generate_reset_token(user)
                print("Reset Token:", reset_token)
                user.reset_token = reset_token
                db.session.commit()

                send_reset_email(user)
                flash('An email has been sent with instructions to reset your password.Please check your inbox.', 'success')
                return redirect(url_for('forgot_password'))

            else:
                print("Email not registered:", email)
                return render_template('email_not_registered.html')

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Initialize error and success variables
    error_message = None
    success_message = None

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            error_message = 'Passwords do not match.'
        else:
            # Validate the token and get the associated user
            user = validate_reset_token(token)

            if user:
                # Update the user's password in the database
                user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
                db.session.commit()

                success_message = 'Password reset successfully. You can now log in with your new password.'
                return render_template('login.html', success=success_message)  # Render login.html directly
            else:
                error_message = 'Invalid reset token.'

    # This line should be outside the else block
    return render_template('reset_password.html', token=token, error=error_message, success=success_message)



@app.route('/input_calories', methods=['GET', 'POST'])
def input_calories():
    weight = float(request.form['weight'])
    height = float(request.form['height'])
    age = int(request.form['age'])
    gender = request.form['gender']

    if gender == 'male':
        calories = (66.47 + (13.75 * weight) + (5.003 * height) - (6.755 * age)) * 1.55
    else:
        calories = (655.1 + (9.563 * weight) + (1.85 * height) - (6.755 * age)) * 1.55
    session['calories'] = calories
    return render_template('calculated_calories.html', calories=calories)


@app.route('/next', methods=['POST'])
def go_to_next_page():
    return render_template('FoodSelect.html')


@app.route('/malay.html')
def malay():
    return render_template('malay.html')


@app.route('/chinese.html')
def chinese():
    return render_template('chinese.html')


@app.route('/indian.html')
def indian():
    return render_template('indian.html')


@app.route('/fastfood.html')
def fastfood():
    return render_template('fastfood.html')


@app.route('/mamak.html')
def mamak():
    return render_template('mamak.html')


@app.route('/dessert.html')
def dessert():
    return render_template('dessert.html')


@app.route('/matchFood', methods=['POST'])
def match_food():
    food_type = request.form.get('foodType')
    food_name = request.form.get('foodName')

    # Query the database for the selected food's information
    selected_food = FoodInformation.query.filter_by(food=food_name).first()

    if selected_food:
        calories = float(session.get('calories', 0))

        # Subtract the food's calories from the stored calories
        calories -= selected_food.calories

        # Update the stored calories in the session
        session['calories'] = calories

        if calories < 0:
            username = str(session.get('username'))
            return render_template('calorie_exceeded.html', dear_user=username)

        record = UserCalories(food=selected_food.food, consumed_calories=selected_food.calories,
                              remaining_calories=calories)
        db.session.add(record)
        db.session.commit()

        return render_template('food_details.html', food_calories=selected_food.calories, current_calories=calories)
    else:
        # Handle the case where the selected food is not found in the database
        return render_template('error.html', message='Food not found in the database')


@app.route('/go_back_to_food_select', methods=['POST'])
def go_back_to_food_select():
    return render_template('FoodSelect.html')


if __name__ == '__main__':
    before_first_request()
    with app.app_context():
        db.create_all()

    app.run(debug=True)
