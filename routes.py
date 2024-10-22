from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash,check_password_hash
from app import app, db


@app.route('/')
def index():
    # use the session object to check if the user is logged in
    if 'user_id' in session:
        return render_template('index.html')
    else:
        flash('Please log in to access the application.', 'info')
        return redirect(url_for('login'))
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    from models import User  # Import the User model here
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']

        # Query for the user
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            # Store the user ID and role in the session
            session['user_id'] = user.id
            session['user_role'] = user.role
            flash(f"Login successful as {user.role}", 'success')

            # Check if the user is an admin
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('index'))  # Redirect to the home page or user dashboard

        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    from models import User  # Import the User model here
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        name = request.form['name']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']  # Ensure you're capturing the role here
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))

        # Validate that the username is unique
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Hash the password for security
        password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user instance
        new_user = User(username=username, name=name, password=password, is_admin=(role == 'admin'), role=role)

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

