from app import db, app
from werkzeug.security import generate_password_hash

# User model representing all users (Admin, Service Professionals, Customers)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)  # True if admin
    role = db.Column(db.String(50), nullable=False)  # 'customer' or 'professional'

# Service model for defining services offered
class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    time_required = db.Column(db.String(50), nullable=False)  # e.g., '2 hours'
    description = db.Column(db.Text, nullable=True)

    service_requests = db.relationship('ServiceRequest', backref='service', lazy=True)
    reviews = db.relationship('Review', backref='service', lazy=True)

# Service Request model representing requests from customers
class ServiceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Optional initially
    date_of_request = db.Column(db.DateTime, nullable=False)
    date_of_completion = db.Column(db.DateTime, nullable=True)
    service_status = db.Column(db.String(50), nullable=False)  # e.g., 'requested', 'assigned', 'closed'
    remarks = db.Column(db.Text, nullable=True)

    reviews = db.relationship('Review', backref='service_request', lazy=True)  # Corrected relationship

# Review model for customer feedback on services
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_request_id = db.Column(db.Integer, db.ForeignKey('service_request.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)  # Added foreign key to Service
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # e.g., 1 to 5
    comment = db.Column(db.Text, nullable=True)

with app.app_context():
    db.create_all()
    #if admin user doesn't exist, create one
    admin = User.query.filter_by(is_admin=True).first()
    if not admin:
        password = generate_password_hash('admin')
        admin = User(username='admin', password=password, name='Admin', is_admin=True, role='admin')
        db.session.add(admin)
        db.session.commit()