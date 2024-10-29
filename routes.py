from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash,check_password_hash
from app import app, db
from datetime import datetime


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
    from models import PendingApproval, ServiceProfessional  # Import the PendingApproval model here
    username = request.form.get("username")
    password = request.form.get("password")
    confirmpassword = request.form.get("confirmpassword")
    name = request.form.get("name")
    email = request.form.get("email")
    service_type = request.form.get("service_type")
    experience = request.form.get("experience")
    description = request.form.get("description")

    # Validate form inputs
    if not (username and password and confirmpassword and name and service_type):
        flash("Please fill out all required fields", 'danger')
        return redirect(url_for("register_service_professional"))

    if password != confirmpassword:
        flash("Password and confirm password do not match", 'danger')
        return redirect(url_for("register_service_professional"))
    
    # Check if username or email already exists in ServiceProfessional or PendingApproval
    if (ServiceProfessional.query.filter_by(username=username).first() or 
        ServiceProfessional.query.filter_by(email=email).first() or
        PendingApproval.query.filter_by(username=username).first() or
        PendingApproval.query.filter_by(email=email).first()):
        flash("Username or Email already exists", 'danger')
        return redirect(url_for("register_service_professional"))
    
    # Create new pending approval entry
    password_hash = generate_password_hash(password)
    new_pending_professional = PendingApproval(
        username=username,
        password=password_hash,
        name=name,
        email=email,
        service_type=service_type,
        experience=experience,
        description=description
    )
    db.session.add(new_pending_professional)
    db.session.commit()
    
    flash("Service Professional registered successfully and is awaiting approval", 'success')
    return redirect(url_for("login_service_professional"))

# Customer Login
@app.route('/customerlogin', methods=['GET', 'POST'])
def customer_login():  # Make sure this name is consistent
    from models import Customer
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        customer = Customer.query.filter_by(username=username).first()

        if not customer:
            flash("Incorrect username or password", 'danger')
            return redirect(url_for("customer_login"))  # Use the correct endpoint name

        if not check_password_hash(customer.password, password):
            flash("Incorrect username or password", 'danger')
            return redirect(url_for("customer_login"))

        if is_user_blocked(customer):
            flash("Your account is blocked. Contact support.", 'danger')
            return redirect(url_for("customer_login"))

        session['customer_id'] = customer.customer_id
        flash("Login successful", 'success')
        return redirect(url_for("customer_dashboard"))

    return render_template('customer_login.html')


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
    return redirect(url_for("professional_dashboard"))

# Logout
@app.route("/logout")
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully", 'info')
    return redirect(url_for("index"))

@app.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    from models import Admin
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password, password):
            session['admin_logged_in'] = True
            flash('Welcome, Admin!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('login_admin.html')  # Create this template for admin login form

@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        flash('Please log in as admin to access the dashboard', 'warning')
        return redirect(url_for('login_admin'))
    return render_template('admin_dashboard.html')

@app.route('/monitor_customers')
def monitor_customers():
    from models import Customer
    customers = Customer.query.all()  # Fetch all customers
    return render_template('monitor_customers.html', customers=customers)

@app.route('/toggle_block/<string:customer_id>')
def toggle_block(customer_id):
    from models import Customer
    customer = Customer.query.get(customer_id)
    if customer:
        customer.is_blocked = not customer.is_blocked  # Toggle block status
        db.session.commit()
        status = "blocked" if customer.is_blocked else "unblocked"
        flash(f'Customer {customer.name} has been {status}.', 'success')
    else:
        flash('Customer not found.', 'danger')
    return redirect(url_for('monitor_customers'))

@app.route('/pending_approval_list')
def pending_approval_list():
    from models import PendingApproval
    pending_professionals = PendingApproval.query.all()
    return render_template('pending_approval_list.html', pending_professionals=pending_professionals)

@app.route('/approve_professional/<int:id>')
def approve_professional(id):
    from models import PendingApproval, ServiceProfessional
    pending_professional = PendingApproval.query.get(id)
    if not pending_professional:
        flash("Professional not found", "danger")
        return redirect(url_for('pending_approval_list'))

    # Approve and move to ServiceProfessional
    new_professional = ServiceProfessional(
        professional_id=generate_professional_id(),
        username=pending_professional.username,
        password=pending_professional.password,
        name=pending_professional.name,
        email=pending_professional.email,
        service_type=pending_professional.service_type,
        experience=pending_professional.experience,
        description=pending_professional.description
    )
    db.session.add(new_professional)
    db.session.delete(pending_professional)
    db.session.commit()

    flash("Professional approved.", "success")
    return redirect(url_for('pending_approval_list'))

@app.route('/reject_professional/<int:id>')
def reject_professional(id):
    from models import PendingApproval
    pending_professional = PendingApproval.query.get(id)
    if not pending_professional:
        flash("Professional not found", "danger")
        return redirect(url_for('pending_approval_list'))

    # Delete the entry from PendingApproval
    db.session.delete(pending_professional)
    db.session.commit()

    flash("Professional rejected and removed from pending list.", "info")
    return redirect(url_for('pending_approval_list'))


@app.route('/admin/view_professionals')
def view_professionals():
    from models import ServiceProfessional
    professionals = ServiceProfessional.query.all()
    return render_template('view_professionals.html', professionals=professionals)

# Route to toggle block/unblock status of a professional
@app.route('/admin/toggle_block/<string:professional_id>', methods=['POST'])
def toggle_block_professional(professional_id):
    from models import ServiceProfessional
    professional = ServiceProfessional.query.get_or_404(professional_id)
    professional.is_blocked = not professional.is_blocked
    db.session.commit()
    action = "unblocked" if not professional.is_blocked else "blocked"
    flash(f"Service professional {professional.name} has been {action}.", 'success')
    return redirect(url_for('view_professionals'))

@app.route('/admin/services', methods=['GET'])
def view_services1():
    from models import Service
    services = Service.query.all()
    return render_template('admin_services.html', services=services)

# Route to create a new service
# Route to display the service creation form
@app.route('/admin/service/create', methods=['GET'])
def show_create_service():
    return render_template('create_service.html')  # Create this HTML template

# Route to handle the form submission
@app.route('/admin/service/create', methods=['POST'])
def create_service():
    from models import Service
    name = request.form.get("name")
    price = request.form.get("price")
    time_required = request.form.get("time_required")
    description = request.form.get("description")
    
    # Validation checks
    if not name or not price or not time_required:
        flash("Please fill in all required fields.", 'danger')
        return redirect(url_for('show_create_service'))  # Redirect back to the form

    # Create new service
    new_service = Service(
        service_id=f"SER{str(Service.query.count() + 1)}",  # Generate a unique service_id
        name=name,
        price=float(price),  # Convert to float
        time_required=time_required,
        description=description
    )
    
    db.session.add(new_service)
    db.session.commit()
    flash("Service created successfully", 'success')
    return redirect(url_for('view_services'))  # Redirect to the service list after creation


# Route to update an existing service
@app.route('/admin/service/update/<string:service_id>', methods=['POST'])
def update_service(service_id):
    from models import Service
    service = Service.query.get_or_404(service_id)
    service.name = request.form.get("name", service.name)
    service.price = request.form.get("price", service.price)
    service.time_required = request.form.get("time_required", service.time_required)
    service.description = request.form.get("description", service.description)
    db.session.commit()
    flash("Service updated successfully", 'success')
    return redirect(url_for('view_services'))

# Route to delete an existing service
@app.route('/admin/service/delete/<string:service_id>', methods=['POST'])
def delete_service(service_id):
    from models import Service
    service = Service.query.get_or_404(service_id)
    db.session.delete(service)
    db.session.commit()
    flash("Service deleted successfully", 'success')
    return redirect(url_for('view_services'))


@app.route('/admin/overview')
def admin_overview():
    from models import Customer, Service, ServiceRequest, ServiceProfessional
    num_users = Customer.query.count()
    num_services = Service.query.count()
    total_bookings = ServiceRequest.query.count()
    total_revenue = db.session.query(db.func.sum(Service.price)).scalar() or 0
    
    # Extra queries for blocked users and approved professionals
    blocked_users = Customer.query.filter_by(is_blocked=True).count()
    approved_professionals = ServiceProfessional.query.filter_by(is_blocked=False).count()
    
    # Pass data to the template for graphs
    return render_template('admin_overview.html', num_users=num_users, num_services=num_services,
                           total_bookings=total_bookings, total_revenue=total_revenue,
                           blocked_users=blocked_users, approved_professionals=approved_professionals)

# Route to view customer dashboard
@app.route('/customer_dashboard')
def customer_dashboard():
    from models import Service, Review
    services = Service.query.all()  # Fetch all services
    customer_id = session.get('customer_id')  # Assuming you're using session
    reviews = Review.query.filter_by(customer_id=customer_id).all()  # Fetch customer reviews
    return render_template('customer_dashboard.html', services=services, reviews=reviews)
    
@app.route('/professional_dashboard')
def professional_dashboard():
    return render_template('professional_dashboard.html')

# Route for viewing pending service requests
@app.route('/professional/pending_requests')
def professional_pending_requests():
    from models import ServiceRequest
    user_id = session.get('user_id')
    pending_requests = ServiceRequest.query.filter_by(service_status='Pending').all()
    return render_template('professional_pending_requests.html', pending_requests=pending_requests)

# Route for accepting a request
@app.route('/professional/accept_request/<request_id>', methods=['POST'])
def accept_request(request_id):
    from models import ServiceRequest
    service_request = ServiceRequest.query.get(request_id)
    if service_request:
        service_request.service_status = 'Accepted'
        service_request.professional_id = session.get('user_id')
        db.session.commit()
        flash("Request accepted successfully.", 'success')
    else:
        flash("Request not found.", 'danger')
    return redirect(url_for('professional_pending_requests'))

# Route for rejecting a request
@app.route('/professional/reject_request/<request_id>', methods=['POST'])
def reject_request(request_id):
    from models import ServiceRequest
    service_request = ServiceRequest.query.get(request_id)
    if service_request:
        service_request.service_status = 'Rejected'
        db.session.commit()
        flash("Request rejected successfully.", 'danger')
    else:
        flash("Request not found.", 'danger')
    return redirect(url_for('professional_pending_requests'))

# Route for viewing completed services
@app.route('/professional/completed_services')
def professional_completed_services():
    from models import ServiceRequest
    user_id = session.get('user_id')
    completed_requests = ServiceRequest.query.filter_by(professional_id=user_id, service_status='Completed').all()
    return render_template('professional_completed_services.html', completed_requests=completed_requests)

# Route for logging out
@app.route('/logout_professional')
def logout_professional():
    session.pop('user_id', None)
    flash("Logout successful.", 'success')
    return redirect(url_for("index"))

@app.route('/request_service', methods=['POST'])
def request_service():
    from models import ServiceRequest
    service_id = request.form.get('service_id')
    remarks = request.form.get('remarks')
    customer_id = session.get('customer_id')  # Assuming you're using session

    # Create and save the service request
    new_request = ServiceRequest(service_id=service_id, customer_id=customer_id, remarks=remarks, service_status='Pending')
    db.session.add(new_request)
    db.session.commit()

    flash('Service request submitted successfully!', 'success')
    return redirect(url_for('customer_dashboard'))

@app.route('/create_request', methods=['GET', 'POST'])
def create_request():
    from models import Service, ServiceProfessional, Customer
    if request.method == 'POST':
        # POST logic for saving request
        pass  # Your existing POST logic here

    # For GET requests
    service_id = request.args.get('service_id')  # Use service_id from the query parameter
    selected_service = Service.query.get(service_id) if service_id else None
    current_customer_id = session.get('customer_id')
    current_customer = Customer.query.get(current_customer_id)

    if current_customer is None:
        flash('Customer not found. Please log in again.', 'danger')
        return redirect(url_for('login'))

    professionals = ServiceProfessional.query.all()
    current_date = datetime.utcnow().date()

    return render_template(
        'create_request.html',
        service_id=selected_service.service_id if selected_service else "",
        customer_id=current_customer.customer_id,
        customer_name=current_customer.name,
        ServiceProfessional=professionals,
        current_date=current_date
    )


# Route to view available services
@app.route('/view_services')
def view_services():
    from models import Service
    services = Service.query.all()
    return render_template('view_services.html', services=services)

# Route to view requests made by the customer
@app.route('/view_requests')
def view_requests():
    from models import ServiceRequest
    customer_id = session.get('customer_id')
    requests = ServiceRequest.query.filter_by(customer_id=customer_id).all()
    return render_template('view_requests.html', requests=requests)

# Route to view requests made by the customer
@app.route('/cancel_request/<string:request_id>')
def cancel_request(request_id):
    from models import ServiceRequest
    request = ServiceRequest.query.get_or_404(request_id)
    if request.service_status == 'Pending':
        db.session.delete(request)
        db.session.commit()
        flash('Service request cancelled successfully', 'success')
    else:
        flash('Cannot cancel request as it is already in progress', 'danger')
    return redirect(url_for('view_requests'))

# Route to edit requests made by the customer
@app.route('/edit_service_request/<request_id>', methods=['GET', 'POST'])
def edit_service_request(request_id):
    from models import ServiceRequest
    service_request = ServiceRequest.query.get_or_404(request_id)  # Get the service request by ID

    if request.method == 'POST':
        # Update the service request fields
        service_request.date_of_request = request.form['date_of_request']
        service_request.service_status = request.form['service_status']
        service_request.remarks = request.form['remarks']
        
        # Commit the changes to the database
        db.session.commit()
        
        flash('Service request updated successfully!', 'success')
        return redirect(url_for('customer_dashboard'))

    return render_template('edit_service_request.html', service_request=service_request)


# Route to view reviews made by the customer
@app.route('/view_reviews')
def view_reviews():
    from models import Review
    customer_id = session.get('customer_id')
    reviews = Review.query.filter_by(customer_id=customer_id).all()
    return render_template('view_reviews.html', reviews=reviews)

#route to Update customer profile
@app.route('/update_customer', methods=['POST'])
def update_customer():
    from models import Customer
    customer_id = session.get('customer_id')
    customer = Customer.query.get_or_404(customer_id)
    customer.name = request.form.get('name', customer.name)
    customer.email = request.form.get('email', customer.email)
    db.session.commit()
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('customer_dashboard'))
