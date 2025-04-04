# app.py
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import uuid
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://neondb_owner:npg_K2El5pFwZjId@ep-shiny-star-a5goso5u-pooler.us-east-2.aws.neon.tech/carpool?sslmode=require'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET', 'super-secret-key')
app.config['UPLOAD_FOLDER'] = 'uploads'
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
    _tablename_ = 'saved_addresses'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    address = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Numeric(10,8))
    longitude = db.Column(db.Numeric(11,8))
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
    _tablename_ = 'notifications'
    
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


@app.route("/")
def home():
    return "Flask App Deployed on Render!"

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
    access_token = create_access_token(identity=user.id)
    
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
    access_token = create_access_token(identity=user.id)
    
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
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    filename = save_file(file)
    
    if not filename:
        return jsonify({'error': 'Invalid file type'}), 400
    
    # Delete old profile picture if exists
    if user.profile_picture:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user.profile_picture))
        except:
            pass
    
    user.profile_picture = filename
    db.session.commit()
    
    return jsonify({
        'message': 'Profile picture uploaded successfully',
        'profile_picture': filename
    })

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
@app.route('/api/rides/search', methods=['GET'])
@jwt_required()
def search_rides():
    # Get query parameters
    pickup_lat = request.args.get('pickup_lat', type=float)
    pickup_lng = request.args.get('pickup_lng', type=float)
    dropoff_lat = request.args.get('dropoff_lat', type=float)
    dropoff_lng = request.args.get('dropoff_lng', type=float)
    ride_type = request.args.get('type')
    departure_time = request.args.get('departure_time')
    
    if not all([pickup_lat, pickup_lng, dropoff_lat, dropoff_lng]):
        return jsonify({'error': 'Pickup and dropoff coordinates are required'}), 400
    
    # Basic query
    query = Ride.query.filter(
        Ride.status == 'pending',
        Ride.departure_time >= datetime.utcnow(),
        Ride.available_seats > 0
    )
    
    # Filter by ride type if provided
    if ride_type:
        query = query.join(Vehicle).filter(Vehicle.type == ride_type)
    
    # Filter by departure time if provided
    if departure_time:
        try:
            departure_datetime = datetime.fromisoformat(departure_time)
            query = query.filter(Ride.departure_time >= departure_datetime)
        except:
            return jsonify({'error': 'Invalid departure time format'}), 400
    
    # TODO: Add distance-based filtering (using PostGIS or simple distance calculation)
    
    rides = query.order_by(Ride.departure_time.asc()).all()
    
    return jsonify([{
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
        'distance': float(ride.distance) if ride.distance else None,
        'duration': ride.duration,
        'created_at': ride.created_at.isoformat()
    } for ride in rides])

@app.route('/api/rides', methods=['POST'])
@jwt_required()
def create_ride():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user.is_driver:
        return jsonify({'error': 'Only drivers can offer rides'}), 403
    
    data = request.get_json()
    
    required_fields = [
        'vehicle_id', 'pickup_address', 'pickup_latitude', 'pickup_longitude',
        'dropoff_address', 'dropoff_latitude', 'dropoff_longitude',
        'departure_time', 'available_seats', 'price_per_seat'
    ]
    
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if vehicle belongs to user
    vehicle = Vehicle.query.filter_by(id=data['vehicle_id'], user_id=user_id).first()
    if not vehicle:
        return jsonify({'error': 'Vehicle not found or does not belong to you'}), 404
    
    # Parse departure time
    try:
        departure_time = datetime.fromisoformat(data['departure_time'])
    except:
        return jsonify({'error': 'Invalid departure time format'}), 400
    
    # Create ride
    ride = Ride(
        driver_id=user_id,
        vehicle_id=data['vehicle_id'],
        pickup_address=data['pickup_address'],
        pickup_latitude=data['pickup_latitude'],
        pickup_longitude=data['pickup_longitude'],
        dropoff_address=data['dropoff_address'],
        dropoff_latitude=data['dropoff_latitude'],
        dropoff_longitude=data['dropoff_longitude'],
        departure_time=departure_time,
        available_seats=data['available_seats'],
        price_per_seat=data['price_per_seat'],
        distance=data.get('distance'),
        duration=data.get('duration')
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
            'status': ride.status
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
    ride = Ride.query.get(ride_id)
    
    if not ride:
        return jsonify({'error': 'Ride not found'}), 404
    
    if ride.driver_id != user_id:
        return jsonify({'error': 'You can only cancel your own rides'}), 403
    
    if ride.status != 'pending':
        return jsonify({'error': 'Only pending rides can be cancelled'}), 400
    
    ride.status = 'cancelled'
    db.session.commit()
    
    # TODO: Notify passengers about cancellation
    
    return jsonify({'message': 'Ride cancelled successfully'})

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
            'id': booking.id,
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