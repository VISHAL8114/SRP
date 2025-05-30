# app.py
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask import send_from_directory
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import uuid
from math import radians, cos, sin, sqrt, atan2
import decimal
from pytz import utc
import cloudinary
import cloudinary.uploader

# Configure Cloudinary
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME", "dtrjgcv4s"),
    api_key=os.getenv("CLOUDINARY_API_KEY", "984652638187289"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET", "P7MWAFCc_NGw10z4Jh_QPkP0gp8"),
    secure=True
)

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://neondb_owner:npg_K2El5pFwZjId@ep-shiny-star-a5goso5u-pooler.us-east-2.aws.neon.tech/carpool?sslmode=require'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET', 'super-secret-key')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)  # Token lasts for 24 hours
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# User Model
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    profile_picture = db.Column(db.Text)
    pan_card = db.Column(db.Text)
    driving_license = db.Column(db.Text)
    is_driver = db.Column(db.Boolean, default=False)
    rating = db.Column(db.Numeric(2, 1), default=5.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    vehicles = db.relationship('Vehicle', backref='owner', lazy=True)
    rides_as_driver = db.relationship('Ride', backref='driver', lazy=True)
    bookings = db.relationship('Booking', backref='passenger', lazy=True)
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    reviews_given = db.relationship('Review', foreign_keys='Review.reviewer_id', backref='reviewer', lazy=True)
    reviews_received = db.relationship('Review', foreign_keys='Review.reviewee_id', backref='reviewee', lazy=True)

# Vehicle Model
class Vehicle(db.Model):
    __tablename__ = 'vehicles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    model = db.Column(db.String(100), nullable=False)
    number = db.Column(db.String(20), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'car', 'bike', 'auto'
    capacity = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    rides = db.relationship('Ride', backref='vehicle', lazy=True)

class SavedAddress(db.Model):
    __tablename__ = 'saved_addresses'  # Corrected tablename syntax
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    address = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Numeric(10, 8))
    longitude = db.Column(db.Numeric(11, 8))
    icon = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Ride(db.Model):
    __tablename__ = 'rides'  # Corrected tablename syntax
    
    id = db.Column(db.Integer, primary_key=True)
    driver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicles.id'))
    pickup_address = db.Column(db.Text, nullable=False)
    pickup_latitude = db.Column(db.Numeric(10, 8), nullable=False)
    pickup_longitude = db.Column(db.Numeric(11, 8), nullable=False)
    dropoff_address = db.Column(db.Text, nullable=False)
    dropoff_latitude = db.Column(db.Numeric(10, 8), nullable=False)
    dropoff_longitude = db.Column(db.Numeric(11, 8), nullable=False)
    departure_time = db.Column(db.DateTime, nullable=False)
    available_seats = db.Column(db.Integer, nullable=False)
    price_per_seat = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'active', 'completed', 'cancelled'
    distance = db.Column(db.Numeric(10, 2))  # in km
    duration = db.Column(db.Integer)  # in minutes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    bookings = db.relationship('Booking', backref='ride', lazy=True)
    messages = db.relationship('Message', backref='ride', lazy=True)

class OfferedRide(db.Model):
    __tablename__ = 'offered_rides'

    id = db.Column(db.Integer, primary_key=True)
    driver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    pickup_address = db.Column(db.Text, nullable=False)
    pickup_latitude = db.Column(db.Numeric(10, 8), nullable=False)
    pickup_longitude = db.Column(db.Numeric(11, 8), nullable=False)
    dropoff_address = db.Column(db.Text, nullable=False)
    dropoff_latitude = db.Column(db.Numeric(10, 8), nullable=False)
    dropoff_longitude = db.Column(db.Numeric(11, 8), nullable=False)
    departure_time = db.Column(db.DateTime, nullable=False)
    available_seats = db.Column(db.Integer, nullable=False)
    price_per_seat = db.Column(db.Numeric(10, 2), nullable=False)
    vehicle_model = db.Column(db.String(50), nullable=False)  # Vehicle model
    vehicle_number = db.Column(db.String(20), nullable=False)  # Vehicle number
    status = db.Column(db.String(20), default='pending')
    distance = db.Column(db.Numeric(10, 2))
    duration = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    driver = db.relationship('User', backref='offered_rides', lazy=True)

class BookedRide(db.Model):
    __tablename__ = 'booked_rides'
    
    id = db.Column(db.Integer, primary_key=True)
    ride_id = db.Column(db.Integer, db.ForeignKey('offered_rides.id'), nullable=False)
    passenger_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    seats_booked = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Numeric(10, 2), nullable=False)
    booking_status = db.Column(db.String(20), default='confirmed')  # 'confirmed', 'cancelled'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    ride = db.relationship('OfferedRide', backref='bookings', lazy=True)

class Booking(db.Model):
    __tablename__ = 'bookings'  # Corrected tablename syntax
    
    id = db.Column(db.Integer, primary_key=True)
    ride_id = db.Column(db.Integer, db.ForeignKey('rides.id'), nullable=False)  # Foreign key to Ride
    passenger_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Foreign key to User
    seats = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.String(20), default='confirmed')  # 'confirmed', 'cancelled', 'completed'
    pickup_location = db.Column(db.Text)
    dropoff_location = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    payments = db.relationship('Payment', backref='booking', lazy=True)
    review = db.relationship('Review', backref='booking', uselist=False, lazy=True)

class Message(db.Model):
    _tablename_ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ride_id = db.Column(db.Integer, db.ForeignKey('rides.id'))
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'ride', 'message', 'promo'
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    reference_id = db.Column(db.Integer)  # ride_id or message_id
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Review(db.Model):
    _tablename_ = 'reviews'
    
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('bookings.id'), nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reviewee_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Payment(db.Model):
    _tablename_ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('bookings.id'), nullable=False)
    amount = db.Column(db.Numeric(10,2), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'pending', 'completed', 'failed'
    transaction_id = db.Column(db.String(100))
    payment_method = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PromoCode(db.Model):
    _tablename_ = 'promo_codes'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    discount_type = db.Column(db.String(10), nullable=False)  # 'percentage', 'fixed'
    discount_value = db.Column(db.Numeric(10,2), nullable=False)
    max_discount = db.Column(db.Numeric(10,2))
    min_order_value = db.Column(db.Numeric(10,2))
    valid_from = db.Column(db.DateTime, nullable=False)
    valid_until = db.Column(db.DateTime, nullable=False)
    max_uses = db.Column(db.Integer)
    current_uses = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Helper Functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def save_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        return unique_filename
    return None

def calculate_distance(lat1, lon1, lat2, lon2):
    # Convert decimal.Decimal to float if necessary
    if isinstance(lat2, decimal.Decimal):
        lat2 = float(lat2)
    if isinstance(lon2, decimal.Decimal):
        lon2 = float(lon2)

    # Haversine formula to calculate distance in kilometers
    R = 6371  # Radius of the Earth in km
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    return R * c

@app.route("/")
def home():
    return "Eco-Commute Deployed on Render! "

# Auth Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['name', 'email', 'phone', 'password']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if user already exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400
    if User.query.filter_by(phone=data['phone']).first():
        return jsonify({'error': 'Phone number already registered'}), 400
    
    # Hash password
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    # Create user
    user = User(
        name=data['name'],
        email=data['email'],
        phone=data['phone'],
        password_hash=hashed_password,
        is_driver=data.get('is_driver', False)
    )
    
    db.session.add(user)
    db.session.commit()
    
    # Generate JWT token
    access_token = create_access_token(identity=str(user.id))  # Convert user.id to string
    
    return jsonify({
        'message': 'User registered successfully',
        'access_token': access_token,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'phone': user.phone,
            'is_driver': user.is_driver,
            'profile_picture': user.profile_picture
        }
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Validate required fields
    if 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Email and password are required'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not bcrypt.check_password_hash(user.password_hash, data['password']):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    # Generate JWT token
    access_token = create_access_token(identity=str(user.id))  # Convert user.id to string
    
    return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'phone': user.phone,
            'is_driver': user.is_driver,
            'profile_picture': user.profile_picture
        }
    })

# User Routes
@app.route('/api/users/me', methods=['GET'])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'phone': user.phone,
        'profile_picture': user.profile_picture,
        'is_driver': user.is_driver,
        'rating': float(user.rating) if user.rating else None,
        'pan_card': user.pan_card,
        'driving_license': user.driving_license
    })

@app.route('/api/users/me', methods=['PUT'])
@jwt_required()
def update_current_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    if 'name' in data:
        user.name = data['name']
    if 'email' in data:
        if User.query.filter(User.email == data['email'], User.id != user_id).first():
            return jsonify({'error': 'Email already in use'}), 400
        user.email = data['email']
    if 'phone' in data:
        if User.query.filter(User.phone == data['phone'], User.id != user_id).first():
            return jsonify({'error': 'Phone number already in use'}), 400
        user.phone = data['phone']
    
    db.session.commit()
    
    return jsonify({'message': 'User updated successfully'})

@app.route('/api/users/me/password', methods=['PUT'])
@jwt_required()
def update_password():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    if 'current_password' not in data or 'new_password' not in data:
        return jsonify({'error': 'Current and new password are required'}), 400
    
    if not bcrypt.check_password_hash(user.password_hash, data['current_password']):
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    user.password_hash = bcrypt.generate_password_hash(data['new_password']).decode('utf-8')
    db.session.commit()
    
    return jsonify({'message': 'Password updated successfully'})

@app.route('/api/users/me/profile-picture', methods=['POST'])
@jwt_required()
def upload_profile_picture():
    user_id = get_jwt_identity()

    # Check if a file is provided
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']

    try:
        # Upload the file to Cloudinary
        result = cloudinary.uploader.upload(
            file,
            folder="profile_pictures",  # Store images in a specific folder
            public_id=f"user_{user_id}",  # Use a unique identifier for the user
            overwrite=True,  # Overwrite the existing image for the user
            resource_type="image"
        )

        # Get the secure URL of the uploaded image
        profile_picture_url = result['secure_url']

        # Update the user's profile picture in the database
        user = User.query.get(user_id)
        if user:
            user.profile_picture = profile_picture_url
            db.session.commit()

        return jsonify({
            "message": "Profile picture uploaded successfully",
            "profile_picture": profile_picture_url
        }), 200

    except Exception as e:
        return jsonify({"error": f"Failed to upload profile picture: {str(e)}"}), 500

@app.route('/api/users/me/pan-card', methods=['POST'])
@jwt_required()
def upload_pan_card():
    user_id = get_jwt_identity()

    # Check if a file is provided
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']

    try:
        # Upload the file to Cloudinary
        result = cloudinary.uploader.upload(
            file,
            folder="pan_cards",  # Store images in a specific folder
            public_id=f"user_{user_id}_pan_card",  # Use a unique identifier for the user
            overwrite=True,  # Overwrite the existing image for the user
            resource_type="image"
        )

        # Get the secure URL of the uploaded image
        pan_card_url = result['secure_url']

        # Update the user's PAN card in the database
        user = User.query.get(user_id)
        if user:
            user.pan_card = pan_card_url
            db.session.commit()

        return jsonify({
            "message": "PAN card uploaded successfully",
            "pan_card": pan_card_url
        }), 200

    except Exception as e:
        return jsonify({"error": f"Failed to upload PAN card: {str(e)}"}), 500

@app.route('/api/users/me/driving-license', methods=['POST'])
@jwt_required()
def upload_driving_license():
    user_id = get_jwt_identity()

    # Check if a file is provided
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']

    try:
        # Upload the file to Cloudinary
        result = cloudinary.uploader.upload(
            file,
            folder="driving_licenses",  # Store images in a specific folder
            public_id=f"user_{user_id}_driving_license",  # Use a unique identifier for the user
            overwrite=True,  # Overwrite the existing image for the user
            resource_type="image"
        )

        # Get the secure URL of the uploaded image
        driving_license_url = result['secure_url']

        # Update the user's driving license in the database
        user = User.query.get(user_id)
        if user:
            user.driving_license = driving_license_url
            db.session.commit()

        return jsonify({
            "message": "Driving license uploaded successfully",
            "driving_license": driving_license_url
        }), 200

    except Exception as e:
        return jsonify({"error": f"Failed to upload driving license: {str(e)}"}), 500

@app.route('/api/users/me/booked-rides', methods=['GET'])
@jwt_required()
def get_booked_rides():
    user_id = get_jwt_identity()
    bookings = BookedRide.query.filter_by(passenger_id=user_id).all()

    return jsonify([{
        'id': booking.id,
        'ride_id': booking.ride_id,
        'pickup_address': booking.ride.pickup_address,
        'dropoff_address': booking.ride.dropoff_address,
        'departure_time': booking.ride.departure_time.isoformat(),
        'seats_booked': booking.seats_booked,
        'total_price': float(booking.total_price),
        'status': booking.booking_status,
        'created_at': booking.created_at.isoformat()
    } for booking in bookings])

@app.route('/api/users/me/offered-rides', methods=['GET'])
@jwt_required()
def get_offered_rides():
    user_id = get_jwt_identity()
    rides = OfferedRide.query.filter_by(driver_id=user_id).all()

    return jsonify([{
        'id': ride.id,
        'pickup_address': ride.pickup_address,
        'dropoff_address': ride.dropoff_address,
        'departure_time': ride.departure_time.isoformat(),
        'available_seats': ride.available_seats,
        'price_per_seat': float(ride.price_per_seat),
        'vehicle_model': ride.vehicle_model,
        'vehicle_number': ride.vehicle_number,
        'status': ride.status,
        'created_at': ride.created_at.isoformat()
    } for ride in rides])

@app.route('/uploads/<filename>', methods=['GET'])
def serve_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
# Similar endpoints for PAN card and driving license uploads would follow the same pattern

# Saved Addresses Routes
@app.route('/api/addresses', methods=['GET'])
@jwt_required()
def get_saved_addresses():
    user_id = get_jwt_identity()
    addresses = SavedAddress.query.filter_by(user_id=user_id).all()
    
    return jsonify([{
        'id': addr.id,
        'name': addr.name,
        'address': addr.address,
        'latitude': float(addr.latitude) if addr.latitude else None,
        'longitude': float(addr.longitude) if addr.longitude else None,
        'icon': addr.icon,
        'created_at': addr.created_at.isoformat()
    } for addr in addresses])

@app.route('/api/addresses', methods=['POST'])
@jwt_required()
def create_saved_address():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if 'name' not in data or 'address' not in data:
        return jsonify({'error': 'Name and address are required'}), 400
    
    address = SavedAddress(
        user_id=user_id,
        name=data['name'],
        address=data['address'],
        latitude=data.get('latitude'),
        longitude=data.get('longitude'),
        icon=data.get('icon', 'home')
    )
    
    db.session.add(address)
    db.session.commit()
    
    return jsonify({
        'message': 'Address saved successfully',
        'address': {
            'id': address.id,
            'name': address.name,
            'address': address.address,
            'latitude': float(address.latitude) if address.latitude else None,
            'longitude': float(address.longitude) if address.longitude else None,
            'icon': address.icon,
            'created_at': address.created_at.isoformat()
        }
    }), 201

@app.route('/api/addresses/<int:address_id>', methods=['PUT'])
@jwt_required()
def update_saved_address(address_id):
    user_id = get_jwt_identity()
    address = SavedAddress.query.filter_by(id=address_id, user_id=user_id).first()
    
    if not address:
        return jsonify({'error': 'Address not found'}), 404
    
    data = request.get_json()
    
    if 'name' in data:
        address.name = data['name']
    if 'address' in data:
        address.address = data['address']
    if 'latitude' in data:
        address.latitude = data['latitude']
    if 'longitude' in data:
        address.longitude = data['longitude']
    if 'icon' in data:
        address.icon = data['icon']
    
    db.session.commit()
    
    return jsonify({'message': 'Address updated successfully'})

@app.route('/api/addresses/<int:address_id>', methods=['DELETE'])
@jwt_required()
def delete_saved_address(address_id):
    user_id = get_jwt_identity()
    address = SavedAddress.query.filter_by(id=address_id, user_id=user_id).first()
    
    if not address:
        return jsonify({'error': 'Address not found'}), 404
    
    db.session.delete(address)
    db.session.commit()
    
    return jsonify({'message': 'Address deleted successfully'})

# Ride Routes
@app.route('/api/rides/search', methods=['POST'])
@jwt_required()
def search_rides():
    user_id = get_jwt_identity()
    data = request.get_json()

    # Validate required fields
    required_fields = ['from', 'to']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'From and To locations are required'}), 400

    from_lat = data['from']['latitude']
    from_lng = data['from']['longitude']
    to_lat = data['to']['latitude']
    to_lng = data['to']['longitude']

    # Get current time and calculate one hour from now
    current_time = datetime.utcnow()
    one_hour_from_now = current_time + timedelta(hours=1)

    # Basic query
    query = OfferedRide.query.filter(
        OfferedRide.status == 'pending',
        OfferedRide.available_seats > 0,
        OfferedRide.departure_time >= current_time,  # Exclude rides with past departure times
        OfferedRide.departure_time >= one_hour_from_now  # Exclude rides departing within the next hour
    )

    # Fetch all rides and filter by route and distance
    rides = query.all()
    matching_rides = []
    for ride in rides:
        # Calculate distance between user's "from" location and ride's pickup location
        pickup_distance = calculate_distance(from_lat, from_lng, ride.pickup_latitude, ride.pickup_longitude)

        # Calculate distance between user's "to" location and ride's dropoff location
        dropoff_distance = calculate_distance(to_lat, to_lng, ride.dropoff_latitude, ride.dropoff_longitude)

        # Check if both pickup and dropoff locations are within 5 km
        if pickup_distance <= 5 and dropoff_distance <= 5:
            # Calculate distance from user's current location to the ride's pickup location
            user_distance = calculate_distance(from_lat, from_lng, ride.pickup_latitude, ride.pickup_longitude)

            matching_rides.append({
                'id': ride.id,
                'driver': {
                    'id': ride.driver.id,
                    'name': ride.driver.name,
                    'profile_picture': ride.driver.profile_picture,
                    'rating': float(ride.driver.rating) if ride.driver.rating else None
                },
                'vehicle': {
                    'model': ride.vehicle_model,
                    'number': ride.vehicle_number
                },
                'pickup_address': ride.pickup_address,
                'pickup_latitude': float(ride.pickup_latitude),
                'pickup_longitude': float(ride.pickup_longitude),
                'dropoff_address': ride.dropoff_address,
                'dropoff_latitude': float(ride.dropoff_latitude),
                'dropoff_longitude': float(ride.dropoff_longitude),
                'departure_time': ride.departure_time.isoformat(),
                'available_seats': ride.available_seats,
                'price_per_seat': float(ride.price_per_seat),
                'distance_from_user': user_distance,
                'duration': ride.duration,
                'created_at': ride.created_at.isoformat()
            })

    # Sort by distance from user's current location
    matching_rides.sort(key=lambda x: x['distance_from_user'])

    return jsonify(matching_rides)

@app.route('/api/rides', methods=['POST'])
@jwt_required()
def create_ride():
    try:
        user_id = get_jwt_identity()
        user = db.session.get(User, user_id)

        if not user.is_driver:
            return jsonify({'error': 'Only drivers can offer rides'}), 403

        data = request.get_json()

        # Validate required fields
        required_fields = [
            'from', 'to', 'date', 'time', 'vehicleModel', 'vehicleNumber',
            'availableSeats', 'pricePerSeat', 'distanceInKm', 'estimatedTravelTime'
        ]
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400

        # Parse departure time
        try:
            departure_time = datetime.strptime(f"{data['date']} {data['time']}", "%Y-%m-%d %H:%M")
        except ValueError:
            return jsonify({'error': 'Invalid date or time format'}), 400

        # Create the ride
        ride = OfferedRide(
            driver_id=user_id,
            pickup_address=data['from']['location'],
            pickup_latitude=data['from']['latitude'],
            pickup_longitude=data['from']['longitude'],
            dropoff_address=data['to']['location'],
            dropoff_latitude=data['to']['latitude'],
            dropoff_longitude=data['to']['longitude'],
            departure_time=departure_time,
            available_seats=data['availableSeats'],
            price_per_seat=data['pricePerSeat'],
            vehicle_model=data['vehicleModel'],
            vehicle_number=data['vehicleNumber'],
            distance=data['distanceInKm'],
            duration=int(data['estimatedTravelTime'].split(':')[0]) * 60 + int(data['estimatedTravelTime'].split(':')[1])
        )

        db.session.add(ride)
        db.session.commit()

        return jsonify({
            'message': 'Ride created successfully',
            'ride': {
                'id': ride.id,
                'pickup_address': ride.pickup_address,
                'dropoff_address': ride.dropoff_address,
                'departure_time': ride.departure_time.isoformat(),
                'available_seats': ride.available_seats,
                'price_per_seat': float(ride.price_per_seat),
                'vehicle_model': ride.vehicle_model,
                'vehicle_number': ride.vehicle_number,
                'status': ride.status
            }
        }), 201

    except Exception as e:
        app.logger.error(f"Error creating ride: {e}")
        return jsonify({'error': 'An internal server error occurred'}), 500

@app.route('/api/rides/<int:ride_id>/book', methods=['POST'])
@jwt_required()
def book_ride(ride_id):
    user_id = get_jwt_identity()
    data = request.get_json()

    # Validate required fields
    if 'seats' not in data:
        return jsonify({'error': 'Number of seats is required'}), 400

    ride = OfferedRide.query.get(ride_id)

    if not ride:
        return jsonify({'error': 'Ride not found'}), 404

    if ride.driver_id == user_id:
        return jsonify({'error': 'You cannot book your own ride'}), 400

    if ride.available_seats < data['seats']:
        return jsonify({'error': 'Not enough seats available'}), 400

    # Calculate total price
    total_price = ride.price_per_seat * data['seats']

    # Create booking
    booking = BookedRide(
        ride_id=ride_id,
        passenger_id=user_id,
        seats_booked=data['seats'],
        total_price=total_price
    )

    # Update available seats
    ride.available_seats -= data['seats']

    db.session.add(booking)
    db.session.commit()

    # Notify the ride giver
    notification = Notification(
        user_id=ride.driver_id,
        type='ride',
        title='New Booking',
        message=f'{booking.seats_booked} seat(s) have been booked by a user.',
        reference_id=ride.id
    )

    db.session.add(notification)
    db.session.commit()

    return jsonify({
        'message': 'Ride booked successfully',
        'booking': {
            'id': booking.id,
            'ride_id': booking.ride_id,
            'seats_booked': booking.seats_booked,
            'total_price': float(booking.total_price),
            'status': booking.booking_status,
            'created_at': booking.created_at.isoformat()
        }
    }), 201

@app.route('/api/rides/<int:ride_id>', methods=['GET'])
@jwt_required()
def get_ride(ride_id):
    ride = Ride.query.get(ride_id)
    
    if not ride:
        return jsonify({'error': 'Ride not found'}), 404
    
    return jsonify({
        'id': ride.id,
        'driver': {
            'id': ride.driver.id,
            'name': ride.driver.name,
            'profile_picture': ride.driver.profile_picture,
            'rating': float(ride.driver.rating) if ride.driver.rating else None
        },
        'vehicle': {
            'id': ride.vehicle.id,
            'model': ride.vehicle.model,
            'number': ride.vehicle.number,
            'type': ride.vehicle.type,
            'capacity': ride.vehicle.capacity
        } if ride.vehicle else None,
        'pickup_address': ride.pickup_address,
        'pickup_latitude': float(ride.pickup_latitude),
        'pickup_longitude': float(ride.pickup_longitude),
        'dropoff_address': ride.dropoff_address,
        'dropoff_latitude': float(ride.dropoff_latitude),
        'dropoff_longitude': float(ride.dropoff_longitude),
        'departure_time': ride.departure_time.isoformat(),
        'available_seats': ride.available_seats,
        'price_per_seat': float(ride.price_per_seat),
        'status': ride.status,
        'distance': float(ride.distance) if ride.distance else None,
        'duration': ride.duration,
        'created_at': ride.created_at.isoformat()
    })

@app.route('/api/rides/<int:ride_id>/cancel', methods=['POST'])
@jwt_required()
def cancel_ride(ride_id):
    user_id = get_jwt_identity()
    ride = db.session.get(OfferedRide, ride_id)

    if not ride:
        return jsonify({'error': 'Ride not found'}), 404

    # Check if the user is the ride giver
    if ride.driver_id == user_id:
        if ride.status != 'pending':
            return jsonify({'error': 'Only pending rides can be cancelled'}), 400

        ride.status = 'cancelled'
        db.session.commit()

        # Notify passengers about the cancellation
        passengers = BookedRide.query.filter_by(ride_id=ride_id).all()
        for booking in passengers:
            notification = Notification(
                user_id=booking.passenger_id,
                type='ride',
                title='Ride Cancelled',
                message=f'The ride you booked has been cancelled by the driver.',
                reference_id=ride.id
            )
            db.session.add(notification)

        db.session.commit()

        return jsonify({'message': 'Ride cancelled successfully'})

    # Check if the user is a passenger
    booking = BookedRide.query.filter_by(ride_id=ride_id, passenger_id=user_id).first()

    if not booking:
        return jsonify({'error': 'You are not part of this ride'}), 403

    if booking.booking_status != 'confirmed':
        return jsonify({'error': 'Only confirmed bookings can be cancelled'}), 400

    booking.booking_status = 'cancelled'
    ride.available_seats += booking.seats_booked  # Add seats back to the ride
    db.session.commit()

    # Notify the ride giver about the cancellation
    notification = Notification(
        user_id=ride.driver_id,
        type='ride',
        title='Booking Cancelled',
        message=f'A passenger has cancelled their booking.',
        reference_id=ride.id
    )

    db.session.add(notification)
    db.session.commit()

    return jsonify({'message': 'Booking cancelled successfully'})

# Booking Routes
@app.route('/api/bookings', methods=['POST'])
@jwt_required()
def create_booking():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    required_fields = ['ride_id', 'seats', 'pickup_location', 'dropoff_location']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    ride = Ride.query.get(data['ride_id'])
    
    if not ride:
        return jsonify({'error': 'Ride not found'}), 404
    
    if ride.status != 'pending':
        return jsonify({'error': 'Ride is not available for booking'}), 400
    
    if ride.available_seats < data['seats']:
        return jsonify({'error': 'Not enough seats available'}), 400
    
    if ride.driver_id == user_id:
        return jsonify({'error': 'You cannot book your own ride'}), 400
    
    # Calculate total price
    total_price = ride.price_per_seat * data['seats']
    
    # Apply promo code if provided
    promo_discount = 0
    if 'promo_code' in data:
        promo_code = PromoCode.query.filter_by(code=data['promo_code'], is_active=True).first()
        
        if promo_code:
            if promo_code.valid_from <= datetime.utcnow() <= promo_code.valid_until:
                if promo_code.max_uses is None or promo_code.current_uses < promo_code.max_uses:
                    if promo_code.min_order_value is None or total_price >= promo_code.min_order_value:
                        if promo_code.discount_type == 'percentage':
                            discount = total_price * (promo_code.discount_value / 100)
                            if promo_code.max_discount:
                                discount = min(discount, promo_code.max_discount)
                            promo_discount = discount
                        else:  # fixed
                            promo_discount = promo_code.discount_value
                        
                        promo_code.current_uses += 1
                        db.session.commit()
    
    total_price -= promo_discount
    
    # Create booking
    booking = Booking(
        ride_id=data['ride_id'],
        passenger_id=user_id,
        seats=data['seats'],
        total_price=total_price,
        pickup_location=data['pickup_location'],
        dropoff_location=data['dropoff_location']
    )
    
    # Update available seats
    ride.available_seats -= data['seats']
    
    db.session.add(booking)
    db.session.commit()
    
    # Create payment record
    payment = Payment(
        booking_id=booking.id,
        amount=total_price,
        status='pending',
        payment_method=data.get('payment_method', 'wallet')
    )
    
    db.session.add(payment)
    db.session.commit()
    
    # TODO: Process payment
    
    # Notify driver
    notification = Notification(
        user_id=ride.driver_id,
        type='ride',
        title='New Booking',
        message=f'{booking.passenger.name} has booked {booking.seats} seat(s) on your ride',
        reference_id=ride.id
    )
    
    db.session.add(notification)
    db.session.commit()
    
    return jsonify({
        'message': 'Booking created successfully',
        'booking': {
            'ride_id': booking.ride_id,
            'seats': booking.seats,
            'total_price': float(booking.total_price),
            'status': booking.status,
            'created_at': booking.created_at.isoformat()
        }
    }), 201

@app.route('/api/bookings/<int:booking_id>/cancel', methods=['POST'])
@jwt_required()
def cancel_booking(booking_id):
    user_id = get_jwt_identity()
    booking = Booking.query.get(booking_id)
    
    if not booking:
        return jsonify({'error': 'Booking not found'}), 404
    
    if booking.passenger_id != user_id:
        return jsonify({'error': 'You can only cancel your own bookings'}), 403
    
    if booking.status != 'confirmed':
        return jsonify({'error': 'Only confirmed bookings can be cancelled'}), 400
    
    ride = booking.ride
    
    if ride.departure_time < datetime.utcnow():
        return jsonify({'error': 'Cannot cancel a ride that has already departed'}), 400
    
    # Update booking status
    booking.status = 'cancelled'
    
    # Return seats to ride
    ride.available_seats += booking.seats
    
    # Refund payment if already processed
    payment = booking.payments[0]
    if payment.status == 'completed':
        # TODO: Process refund
        pass
    
    db.session.commit()
    
    # Notify driver
    notification = Notification(
        user_id=ride.driver_id,
        type='ride',
        title='Booking Cancelled',
        message=f'{booking.passenger.name} has cancelled their booking',
        reference_id=ride.id
    )
    
    db.session.add(notification)
    db.session.commit()
    
    return jsonify({'message': 'Booking cancelled successfully'})

# Message Routes
@app.route('/api/messages', methods=['GET'])
@jwt_required()
def get_messages():
    user_id = get_jwt_identity()
    
    # Get conversations (group by other user)
    conversations = db.session.query(
        db.func.greatest(Message.sender_id, Message.receiver_id).label('user1'),
        db.func.least(Message.sender_id, Message.receiver_id).label('user2'),
        db.func.max(Message.id).label('last_message_id')
    ).filter(
        (Message.sender_id == user_id) | (Message.receiver_id == user_id)
    ).group_by(
        'user1', 'user2'
    ).all()
    
    # Get last message details for each conversation
    messages = []
    for conv in conversations:
        other_user_id = conv.user1 if conv.user1 != user_id else conv.user2
        other_user = User.query.get(other_user_id)
        last_message = Message.query.get(conv.last_message_id)
        
        messages.append({
            'user': {
                'id': other_user.id,
                'name': other_user.name,
                'profile_picture': other_user.profile_picture
            },
            'last_message': {
                'content': last_message.content,
                'is_read': last_message.is_read,
                'created_at': last_message.created_at.isoformat()
            },
            'unread_count': Message.query.filter(
                Message.sender_id == other_user_id,
                Message.receiver_id == user_id,
                Message.is_read == False
            ).count()
        })
    
    return jsonify(messages)

@app.route('/api/messages/<int:user_id>', methods=['GET'])
@jwt_required()
def get_conversation(user_id):
    current_user_id = get_jwt_identity()
    other_user = User.query.get(user_id)
    
    if not other_user:
        return jsonify({'error': 'User not found'}), 404
    
    messages = Message.query.filter(
        ((Message.sender_id == current_user_id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user_id))
    ).order_by(Message.created_at.asc()).all()
    
    # Mark messages as read
    Message.query.filter(
        Message.sender_id == user_id,
        Message.receiver_id == current_user_id,
        Message.is_read == False
    ).update({'is_read': True})
    db.session.commit()
    
    return jsonify([{
        'id': msg.id,
        'sender_id': msg.sender_id,
        'content': msg.content,
        'is_read': msg.is_read,
        'created_at': msg.created_at.isoformat()
    } for msg in messages])

@app.route('/api/messages', methods=['POST'])
@jwt_required()
def send_message():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    if 'receiver_id' not in data or 'content' not in data:
        return jsonify({'error': 'Receiver ID and content are required'}), 400
    
    if current_user_id == data['receiver_id']:
        return jsonify({'error': 'Cannot send message to yourself'}), 400
    
    receiver = User.query.get(data['receiver_id'])
    
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404
    
    message = Message(
        sender_id=current_user_id,
        receiver_id=data['receiver_id'],
        ride_id=data.get('ride_id'),
        content=data['content']
    )
    
    db.session.add(message)
    db.session.commit()
    
    # Create notification for receiver
    notification = Notification(
        user_id=data['receiver_id'],
        type='message',
        title='New Message',
        message=f'You have a new message from {message.sender.name}',
        reference_id=message.id
    )
    
    db.session.add(notification)
    db.session.commit()
    
    return jsonify({
        'message': 'Message sent successfully',
        'message': {
            'id': message.id,
            'content': message.content,
            'created_at': message.created_at.isoformat()
        }
    }), 201

# Notification Routes
@app.route('/api/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user_id = get_jwt_identity()
    notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).all()
    
    return jsonify([{
        'id': notif.id,
        'type': notif.type,
        'title': notif.title,
        'message': notif.message,
        'is_read': notif.is_read,
        'reference_id': notif.reference_id,
        'created_at': notif.created_at.isoformat()
    } for notif in notifications])

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@jwt_required()
def mark_notification_read(notification_id):
    user_id = get_jwt_identity()
    notification = Notification.query.filter_by(id=notification_id, user_id=user_id).first()
    
    if not notification:
        return jsonify({'error': 'Notification not found'}), 404
    
    notification.is_read = True
    db.session.commit()
    
    return jsonify({'message': 'Notification marked as read'})

# Review Routes
@app.route('/api/reviews', methods=['POST'])
@jwt_required()
def create_review():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    required_fields = ['booking_id', 'reviewee_id', 'rating']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    booking = Booking.query.get(data['booking_id'])
    
    if not booking:
        return jsonify({'error': 'Booking not found'}), 404
    
    if booking.passenger_id != user_id:
        return jsonify({'error': 'You can only review rides you have booked'}), 403
    
    if booking.status != 'completed':
        return jsonify({'error': 'You can only review completed rides'}), 400
    
    if booking.review:
        return jsonify({'error': 'You have already reviewed this ride'}), 400
    
    reviewee = User.query.get(data['reviewee_id'])
    
    if not reviewee:
        return jsonify({'error': 'User being reviewed not found'}), 404
    
    if reviewee.id != booking.ride.driver_id:
        return jsonify({'error': 'You can only review the driver of your ride'}), 400
    
    if not 1 <= data['rating'] <= 5:
        return jsonify({'error': 'Rating must be between 1 and 5'}), 400
    
    review = Review(
        booking_id=data['booking_id'],
        reviewer_id=user_id,
        reviewee_id=data['reviewee_id'],
        rating=data['rating'],
        comment=data.get('comment')
    )
    
    db.session.add(review)
    
    # Update reviewee's average rating
    reviewee_reviews = Review.query.filter_by(reviewee_id=reviewee.id).all()
    total_ratings = sum([r.rating for r in reviewee_reviews]) + data['rating']
    average_rating = total_ratings / (len(reviewee_reviews) + 1)
    reviewee.rating = average_rating
    
    db.session.commit()
    
    return jsonify({
        'message': 'Review submitted successfully',
        'review': {
            'id': review.id,
            'rating': review.rating,
            'comment': review.comment,
            'created_at': review.created_at.isoformat()
        }
    }), 201

# Vehicle Routes
@app.route('/api/vehicles', methods=['GET'])
@jwt_required()
def get_vehicles():
    user_id = get_jwt_identity()
    vehicles = Vehicle.query.filter_by(user_id=user_id).all()
    
    return jsonify([{
        'id': vehicle.id,
        'model': vehicle.model,
        'number': vehicle.number,
        'type': vehicle.type,
        'capacity': vehicle.capacity,
        'created_at': vehicle.created_at.isoformat()
    } for vehicle in vehicles])

@app.route('/api/vehicles', methods=['POST'])
@jwt_required()
def create_vehicle():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    required_fields = ['model', 'number', 'type', 'capacity']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if data['type'] not in ['car', 'bike', 'auto']:
        return jsonify({'error': 'Invalid vehicle type'}), 400
    
    vehicle = Vehicle(
        user_id=user_id,
        model=data['model'],
        number=data['number'],
        type=data['type'],
        capacity=data['capacity']
    )
    
    db.session.add(vehicle)
    db.session.commit()
    
    return jsonify({
        'message': 'Vehicle added successfully',
        'vehicle': {
            'id': vehicle.id,
            'model': vehicle.model,
            'number': vehicle.number,
            'type': vehicle.type,
            'capacity': vehicle.capacity
        }
    }), 201

@app.route('/api/vehicles/<int:vehicle_id>', methods=['PUT'])
@jwt_required()
def update_vehicle(vehicle_id):
    user_id = get_jwt_identity()
    vehicle = Vehicle.query.filter_by(id=vehicle_id, user_id=user_id).first()
    
    if not vehicle:
        return jsonify({'error': 'Vehicle not found'}), 404
    
    data = request.get_json()
    
    if 'model' in data:
        vehicle.model = data['model']
    if 'number' in data:
        vehicle.number = data['number']
    if 'type' in data:
        if data['type'] not in ['car', 'bike', 'auto']:
            return jsonify({'error': 'Invalid vehicle type'}), 400
        vehicle.type = data['type']
    if 'capacity' in data:
        vehicle.capacity = data['capacity']
    
    db.session.commit()
    
    return jsonify({'message': 'Vehicle updated successfully'})

@app.route('/api/vehicles/<int:vehicle_id>', methods=['DELETE'])
@jwt_required()
def delete_vehicle(vehicle_id):
    user_id = get_jwt_identity()
    vehicle = Vehicle.query.filter_by(id=vehicle_id, user_id=user_id).first()
    
    if not vehicle:
        return jsonify({'error': 'Vehicle not found'}), 404
    
    # Check if vehicle is associated with any active rides
    active_rides = Ride.query.filter(
        Ride.vehicle_id == vehicle_id,
        Ride.status.in_(['pending', 'active'])
    ).count()
    
    if active_rides > 0:
        return jsonify({'error': 'Cannot delete vehicle associated with active rides'}), 400
    
    db.session.delete(vehicle)
    db.session.commit()
    
    return jsonify({'message': 'Vehicle deleted successfully'})

# Ride History Routes
@app.route('/api/rides/history', methods=['GET'])
@jwt_required()
def get_ride_history():
    user_id = get_jwt_identity()
    
    # As driver
    driver_rides = Ride.query.filter_by(driver_id=user_id).all()
    
    # As passenger
    passenger_bookings = Booking.query.filter_by(passenger_id=user_id).all()
    passenger_rides = [booking.ride for booking in passenger_bookings]
    
    # Combine and sort
    all_rides = driver_rides + passenger_rides
    all_rides.sort(key=lambda x: x.departure_time, reverse=True)
    
    return jsonify([{
        'id': ride.id,
        'driver': {
            'id': ride.driver.id,
            'name': ride.driver.name,
            'profile_picture': ride.driver.profile_picture
        },
        'vehicle': {
            'model': ride.vehicle.model,
            'number': ride.vehicle.number,
            'type': ride.vehicle.type
        } if ride.vehicle else None,
        'pickup_address': ride.pickup_address,
        'dropoff_address': ride.dropoff_address,
        'departure_time': ride.departure_time.isoformat(),
        'status': ride.status,
        'distance': float(ride.distance) if ride.distance else None,
        'duration': ride.duration,
        'created_at': ride.created_at.isoformat(),
        'role': 'driver' if ride.driver_id == user_id else 'passenger',
        'booking_id': next((b.id for b in passenger_bookings if b.ride_id == ride.id), None)
    } for ride in all_rides])

# Earnings Routes
@app.route('/api/earnings', methods=['GET'])
@jwt_required()
def get_earnings():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user.is_driver:
        return jsonify({'error': 'Only drivers can view earnings'}), 403
    
    # Get time period from query params
    period = request.args.get('period', 'week')  # 'week', 'month', 'year'
    
    # Calculate date range
    now = datetime.utcnow()
    if period == 'week':
        start_date = now - timedelta(days=7)
    elif period == 'month':
        start_date = now - timedelta(days=30)
    elif period == 'year':
        start_date = now - timedelta(days=365)
    else:
        return jsonify({'error': 'Invalid period'}), 400
    
    # Get completed rides in the period
    rides = Ride.query.filter(
        Ride.driver_id == user_id,
        Ride.status == 'completed',
        Ride.created_at >= start_date
    ).all()
    
    # Calculate stats
    total_earnings = sum(float(ride.price_per_seat * (ride.vehicle.capacity - ride.available_seats)) for ride in rides)
    total_rides = len(rides)
    total_distance = sum(float(ride.distance) for ride in rides if ride.distance)
    
    # Get ride history for the period
    ride_history = []
    for ride in rides:
        passengers = Booking.query.filter_by(ride_id=ride.id).count()
        ride_history.append({
            'id': ride.id,
            'date': ride.created_at.strftime('%b %d'),
            'from': ride.pickup_address.split(',')[0],
            'to': ride.dropoff_address.split(',')[0],
            'amount': float(ride.price_per_seat * passengers),
            'time': ride.departure_time.strftime('%I:%M %p'),
            'passengers': passengers
        })
    
    return jsonify({
        'total': total_earnings,
        'rides': total_rides,
        'distance': total_distance,
        'history': ride_history
    })

# Track Ride Routes
@app.route('/api/rides/<int:ride_id>/track', methods=['GET'])
@jwt_required()
def track_ride(ride_id):
    user_id = get_jwt_identity()
    ride = Ride.query.get(ride_id)
    
    if not ride:
        return jsonify({'error': 'Ride not found'}), 404
    
    # Check if user is driver or passenger
    is_driver = ride.driver_id == user_id
    is_passenger = Booking.query.filter_by(ride_id=ride_id, passenger_id=user_id).first() is not None
    
    if not (is_driver or is_passenger):
        return jsonify({'error': 'You are not part of this ride'}), 403
    
    # Get driver's current location (in a real app, this would come from GPS)
    # For demo, we'll just return the pickup location
    current_location = {
        'latitude': float(ride.pickup_latitude),
        'longitude': float(ride.pickup_longitude)
    }
    
    # Calculate ETA (in a real app, this would use a mapping service)
    eta = 10  # minutes
    
    return jsonify({
        'ride': {
            'id': ride.id,
            'pickup': {
                'address': ride.pickup_address,
                'latitude': float(ride.pickup_latitude),
                'longitude': float(ride.pickup_longitude)
            },
            'dropoff': {
                'address': ride.dropoff_address,
                'latitude': float(ride.dropoff_latitude),
                'longitude': float(ride.dropoff_longitude)
            },
            'status': ride.status,
            'departure_time': ride.departure_time.isoformat()
        },
        'driver': {
            'id': ride.driver.id,
            'name': ride.driver.name,
            'profile_picture': ride.driver.profile_picture,
            'rating': float(ride.driver.rating) if ride.driver.rating else None
        },
        'vehicle': {
            'model': ride.vehicle.model,
            'number': ride.vehicle.number,
            'type': ride.vehicle.type
        } if ride.vehicle else None,
        'current_location': current_location,
        'eta': eta
    })

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))