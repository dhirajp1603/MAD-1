from app import db, app
from werkzeug.security import generate_password_hash
from datetime import datetime

def generate_professional_id():
    last_professional = ServiceProfessional.query.order_by(ServiceProfessional.professional_id.desc()).first()
    if last_professional:
        last_id = int(last_professional.professional_id.replace("PRO", ""))
        new_id = f"PRO{last_id + 1}"
    else:
        new_id = "PRO1"
    return new_id

def generate_service_id():
    last_service = Service.query.order_by(Service.service_id.desc()).first()
    if last_service:
        last_id = int(last_service.service_id.replace("SER", ""))
        new_id = f"SER{last_id + 1}"
    else:
        new_id = "SER1"
    return new_id


class Admin(db.Model):
    __tablename__ = 'admins'
    admin_id = db.Column(db.String(100), primary_key=True, default="AD1")  # Single Admin
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True)

class ServiceProfessional(db.Model):
    __tablename__ = 'service_professionals'
    professional_id = db.Column(db.String(100), primary_key=True, default=generate_professional_id)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    service_type = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.Integer)
    description = db.Column(db.Text)
    pincode = db.Column(db.String(10), nullable=False)
    is_blocked = db.Column(db.Boolean, default=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    reviews = db.relationship('Review', backref='professional', cascade="all, delete-orphan")

class Customer(db.Model):
    __tablename__ = 'customers'
    customer_id = db.Column(db.String(100), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    is_blocked = db.Column(db.Boolean, default=False)
    service_requests = db.relationship('ServiceRequest', backref='customer', cascade="all, delete-orphan")
    reviews = db.relationship('Review', backref='customer', cascade="all, delete-orphan")

class Service(db.Model):
    __tablename__ = 'services'
    service_id = db.Column(db.String(100), primary_key=True, default=generate_service_id)
    name = db.Column(db.String(100), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    time_required = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    service_requests = db.relationship('ServiceRequest', backref='service', cascade="all, delete-orphan")
    reviews = db.relationship('Review', backref='service', cascade="all, delete-orphan")

class ServiceRequest(db.Model):
    __tablename__ = 'service_requests'
    request_id = db.Column(db.String(100), primary_key=True)
    service_id = db.Column(db.String(100), db.ForeignKey('services.service_id'), nullable=False)
    customer_id = db.Column(db.String(100), db.ForeignKey('customers.customer_id'), nullable=False)
    professional_id = db.Column(db.String(100), db.ForeignKey('service_professionals.professional_id'), nullable=True)
    date_of_request = db.Column(db.DateTime, default=datetime.utcnow)
    date_of_completion = db.Column(db.DateTime)
    service_status = db.Column(db.String(50), nullable=False)
    remarks = db.Column(db.Text)
    review = db.relationship('Review', backref='related_request', uselist=False, cascade="all, delete-orphan")
    professional = db.relationship('ServiceProfessional', backref='requests')


class Review(db.Model):
    __tablename__ = 'reviews'
    review_id = db.Column(db.String(100), primary_key=True)
    request_id = db.Column(db.String(100), db.ForeignKey('service_requests.request_id'), nullable=False)
    service_id = db.Column(db.String(100), db.ForeignKey('services.service_id'), nullable=False)
    customer_id = db.Column(db.String(100), db.ForeignKey('customers.customer_id'), nullable=False)
    professional_id = db.Column(db.String(100), db.ForeignKey('service_professionals.professional_id'), nullable=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    review_submitted = db.Column(db.Boolean, default=False, nullable=False)


class PendingApproval(db.Model):
    __tablename__ = 'pending_approval'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    service_type = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.Integer)
    description = db.Column(db.Text)
    pincode = db.Column(db.String(10), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()
    #if admin user doesn't exist, create one
    admin = Admin.query.filter_by(admin_id="AD1").first()
    if not admin:
        password = generate_password_hash('admin')
        admin = Admin(username='admin', password=password, name='Admin')
        db.session.add(admin)
        db.session.commit()
