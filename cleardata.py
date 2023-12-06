from app import app, db, User

# Assuming "your_flask_app" is the name of your Flask application instance
# and "User" is your User model

def clear_user_table():
    with app.app_context():
        # Delete all records from the User table
        db.session.query(User).delete()

        # Commit the changes
        db.session.commit()

# Call the function to clear the User table
clear_user_table()
