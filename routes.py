from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash,check_password_hash
from app import app, db


# Utility functions for ID generation
def generate_professional_id():
    from models import Customer, ServiceProfessional  # Import the models here
    last_professional = ServiceProfessional.query.order_by(ServiceProfessional.professional_id.desc()).first()
    if last_professional:
        last_id = int(last_professional.professional_id.replace("PRO", ""))
        new_id = f"PRO{last_id + 1}"
    else:
        new_id = "PRO1"
    return new_id

def generate_customer_id():
    from models import Customer, ServiceProfessional  # Import the models here
    last_customer = Customer.query.order_by(Customer.customer_id.desc()).first()
    if last_customer:
        last_id = int(last_customer.customer_id.replace("CUS", ""))
        new_id = f"CUS{last_id + 1}"
    else:
        new_id = "CUS1"
    return new_id

# Check if user is blocked
def is_user_blocked(user):
    if user.is_blocked:
        return True
    return False


# Home route
@app.route('/')
def index():
    user_id = session.get('user_id')
    if user_id:
        if user_id.startswith('CUS'):
            return render_template('index.html')
        elif user_id.startswith('PRO'):
            return render_template('professional_dashboard.html')
        return render_template('admin_dashboard.html')
    flash('Please log in to access the application.', 'info')
    return redirect(url_for('login'))

# Registration and Login page separators
@app.route("/register")
def register():
    return render_template("registerseparator.html")

@app.route("/login")
def login():
    return render_template("loginseparator.html")

@app.route("/register_customer")
def register_customer():
    return render_template("register_customer.html")

@app.route("/register_service_professional")
def register_service_professional():
    return render_template("register_Service_Professional.html")

@app.route("/login_customer")
def login_customer():
    return render_template("customer_login.html")

@app.route("/login_service_professional")
def login_service_professional():
    return render_template("Service_Professional_login.html")

# Customer Registration
@app.route("/customerregister", methods=["POST"])
def customerregister_post():
    from models import Customer # Import the models here
    username = request.form.get("username")
    password = request.form.get("password")
    confirmpassword = request.form.get("confirmpassword")
    name = request.form.get("name")
    email = request.form.get("email")
    
    if not (username and password and confirmpassword and name):
        flash("Please fill out all required fields", 'danger')
        return redirect(url_for("register_customer"))

    if password != confirmpassword:
        flash("Password and confirm password do not match", 'danger')
        return redirect(url_for("register_customer"))
    
    # Check if username or email already exists
    if Customer.query.filter_by(username=username).first() or Customer.query.filter_by(email=email).first():
        flash("Username or Email already exists", 'danger')
        return redirect(url_for("register_customer"))
    
    # Create new customer
    password_hash = generate_password_hash(password)
    new_customer = Customer(
        customer_id=generate_customer_id(),
        username=username,
        password=password_hash,
        name=name,
        email=email
    )
    db.session.add(new_customer)
    db.session.commit()
    flash("Customer registered successfully", 'success')
    return redirect(url_for("login_customer"))

# Service Professional Registration
@app.route("/professionalregister", methods=["POST"])
def professionalregister_post():
    from models import ServiceProfessional  # Import the models here
    username = request.form.get("username")
    password = request.form.get("password")
    confirmpassword = request.form.get("confirmpassword")
    name = request.form.get("name")
    email = request.form.get("email")
    service_type = request.form.get("service_type")
    experience = request.form.get("experience")
    description = request.form.get("description")

    if not (username and password and confirmpassword and name and service_type):
        flash("Please fill out all required fields", 'danger')
        return redirect(url_for("register_service_professional"))

    if password != confirmpassword:
        flash("Password and confirm password do not match", 'danger')
        return redirect(url_for("register_service_professional"))
    
    # Check if username or email already exists
    if ServiceProfessional.query.filter_by(username=username).first() or ServiceProfessional.query.filter_by(email=email).first():
        flash("Username or Email already exists", 'danger')
        return redirect(url_for("register_service_professional"))
    
    # Create new service professional
    password_hash = generate_password_hash(password)
    new_professional = ServiceProfessional(
        professional_id=generate_professional_id(),
        username=username,
        password=password_hash,
        name=name,
        email=email,
        service_type=service_type,
        experience=experience,
        description=description
    )
    db.session.add(new_professional)
    db.session.commit()
    flash("Service Professional registered successfully", 'success')
    return redirect(url_for("login_service_professional"))

# Customer Login
@app.route('/customerlogin', methods=['POST'])
def customerlogin_post():
    from models import Customer  # Import the models here
    username = request.form.get('username')
    password = request.form.get('password')
    
    customer = Customer.query.filter_by(username=username).first()

    if not customer or not check_password_hash(customer.password, password):
        flash("Incorrect username or password", 'danger')
        return redirect(url_for("login_customer"))

    if is_user_blocked(customer):
        flash("Your account is blocked. Contact support.", 'danger')
        return redirect(url_for("login_customer"))
    
    session['user_id'] = customer.customer_id
    flash("Login successful", 'success')
    return redirect(url_for("index"))

# Service Professional Login
@app.route('/professionallogin', methods=['POST'])
def professionallogin_post():
    from models import ServiceProfessional
    username = request.form.get('username')
    password = request.form.get('password')
    
    professional = ServiceProfessional.query.filter_by(username=username).first()

    if not professional or not check_password_hash(professional.password, password):
        flash("Incorrect username or password", 'danger')
        return redirect(url_for("login_service_professional"))

    if is_user_blocked(professional):
        flash("Your account is blocked. Contact support.", 'danger')
        return redirect(url_for("login_service_professional"))
    
    session['user_id'] = professional.professional_id
    flash("Login successful", 'success')
    return redirect(url_for("index"))

# Logout
@app.route("/logout")
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully", 'info')
    return redirect(url_for("index"))