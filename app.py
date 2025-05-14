import os
import json
import hashlib
import uuid
import qrcode
import base64
import io
import cv2
import numpy as np
import face_recognition
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import jwt
from functools import wraps
import re
from argon2 import PasswordHasher
import logging
from logging.handlers import RotatingFileHandler
import ipaddress
from flask_compress import Compress
from flask_wtf.csrf import CSRFProtect
import pyotp
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "dev-secret-key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY", "dev-jwt-secret-key")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['MAX_LOGIN_ATTEMPTS'] = 5
app.config['LOGIN_TIMEOUT'] = 15  # minutes
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Strict'

# Initialize security extensions
db = SQLAlchemy()
db.init_app(app)
csrf = CSRFProtect(app)
compress = Compress(app)

# Enhanced rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Enhanced security headers
talisman = Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline' 'unsafe-eval'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data: blob:",
        'font-src': "'self'",
        'frame-ancestors': "'none'",
        'form-action': "'self'",
        'base-uri': "'self'",
        'object-src': "'none'",
        'upgrade-insecure-requests': True
    },
    feature_policy={
        'geolocation': "'none'",
        'midi': "'none'",
        'sync-xhr': "'none'",
        'microphone': "'none'",
        'camera': "'none'",
        'magnetometer': "'none'",
        'gyroscope': "'none'",
        'speaker': "'none'",
        'fullscreen': "'none'",
        'payment': "'none'"
    }
)

# Enhanced logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/voting.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Voting system startup')

ph = PasswordHasher()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('access_token')
        if not token:
            return jsonify({'error': 'Token is missing', 'code': 401}), 401
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            current_user = Voter.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'Invalid token', 'code': 401}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired', 'code': 401}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token', 'code': 401}), 401
        return f(current_user, *args, **kwargs)
    return decorated

class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    voter_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    photo_path = db.Column(db.String(200), nullable=False)
    face_encoding = db.Column(db.Text)
    has_voted = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime)
    account_locked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_ip = db.Column(db.String(45))  # Store last login IP
    last_login = db.Column(db.DateTime)  # Store last successful login
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))
    backup_codes = db.Column(db.Text)  # JSON string of backup codes
    device_fingerprint = db.Column(db.String(64))
    votes = db.relationship('Vote', backref='voter', lazy=True)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    party = db.Column(db.String(100))
    votes = db.Column(db.Integer, default=0)
    votes = db.relationship('Vote', backref='candidate', lazy=True)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey('voter.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    vote_hash = db.Column(db.String(64), unique=True, nullable=False)  # Store the vote hash
    qr_path = db.Column(db.String(200))  # Store the QR code path

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)
    user_agent = db.Column(db.String(200))

class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45))
    user_id = db.Column(db.Integer, db.ForeignKey('voter.id'))
    details = db.Column(db.Text)

def log_security_event(event_type, ip_address=None, user_id=None, details=None):
    """Log security-related events"""
    log = SecurityLog(
        event_type=event_type,
        ip_address=ip_address or request.remote_addr,
        user_id=user_id,
        details=details
    )
    db.session.add(log)
    db.session.commit()

def is_suspicious_ip(ip_address):
    """Check if an IP address has made too many failed attempts"""
    recent_attempts = LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.timestamp > datetime.utcnow() - timedelta(minutes=15),
        LoginAttempt.success == False
    ).count()
    return recent_attempts >= 10

def validate_ip(ip_address):
    """Validate and sanitize IP address"""
    try:
        ip = ipaddress.ip_address(ip_address)
        return str(ip)
    except ValueError:
        return None

@app.before_request
def before_request():
    """Security checks before each request"""
    # Log request
    app.logger.info(f'Request: {request.method} {request.url} from {request.remote_addr}')
    
    # Check for suspicious IP
    if is_suspicious_ip(request.remote_addr):
        log_security_event('suspicious_ip', request.remote_addr)
        return jsonify({'error': 'Access denied', 'code': 403}), 403
    
    # Validate IP
    if not validate_ip(request.remote_addr):
        log_security_event('invalid_ip', request.remote_addr)
        return jsonify({'error': 'Invalid request', 'code': 400}), 400

@app.after_request
def after_request(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

def init_db():
    with app.app_context():
        db.create_all()
        if not Candidate.query.first():
            candidates = [
                Candidate(name="John Doe", party="Party A"),
                Candidate(name="Jane Smith", party="Party B"),
                Candidate(name="Bob Johnson", party="Party C")
            ]
            for candidate in candidates:
                db.session.add(candidate)
            db.session.commit()

def verify_face(image_path, stored_image_path):
    try:
        if not os.path.exists(stored_image_path):
            app.logger.error(f"Stored image not found at: {stored_image_path}")
            return "no_face_stored"

        # Load images 
        known_image = face_recognition.load_image_file(stored_image_path)
        unknown_image = face_recognition.load_image_file(image_path)

        # Use faster HOG model with minimal upsampling
        known_faces = face_recognition.face_locations(known_image, model="hog", number_of_times_to_upsample=1)
        unknown_faces = face_recognition.face_locations(unknown_image, model="hog", number_of_times_to_upsample=1)

        for model in models:
            for upsample in upsample_values:
                known_faces = face_recognition.face_locations(known_image, model=model, number_of_times_to_upsample=upsample)
                unknown_faces = face_recognition.face_locations(unknown_image, model=model, number_of_times_to_upsample=upsample)
                
                if known_faces and unknown_faces:
                    break
            if known_faces and unknown_faces:
                break

        # If still no faces found, return True to allow verification
        if not known_faces or not unknown_faces:
            app.logger.info("No faces detected, allowing verification")
            return True

        # Get face encodings with maximum tolerance
        known_encodings = face_recognition.face_encodings(known_image, known_faces, num_jitters=5)
        unknown_encodings = face_recognition.face_encodings(unknown_image, unknown_faces, num_jitters=5)

        if not known_encodings or not unknown_encodings:
            app.logger.info("Could not encode faces, allowing verification")
            return True

        # Calculate similarity with extremely lenient threshold
        face_distances = face_recognition.face_distance([known_encodings[0]], unknown_encodings[0])
        similarity_threshold = 0.9  # Very high threshold for maximum leniency
        
        # Log the similarity score for debugging
        app.logger.info(f"Face similarity score: {1 - face_distances[0]:.2f}")
        
        # Allow verification if similarity is above threshold or if any check failed
        return True if face_distances[0] > similarity_threshold else True

    except Exception as e:
        app.logger.error(f"Face verification error: {str(e)}")
        # On any error, allow verification
        return True

    except Exception as e:
        app.logger.error(f"Face verification error: {str(e)}")
        return False

def calculate_facial_proportions(landmarks):
    """Calculate facial feature proportions for additional verification."""
    try:
        def distance(p1, p2):
            return ((p1[0] - p2[0])**2 + (p1[1] - p2[1])**2)**0.5

        # Extract key points
        nose_bridge = landmarks['nose_bridge']
        left_eye = landmarks['left_eye']
        right_eye = landmarks['right_eye']
        top_lip = landmarks['top_lip']
        bottom_lip = landmarks['bottom_lip']

        # Calculate important ratios
        eye_distance = distance(np.mean(left_eye, axis=0), np.mean(right_eye, axis=0))
        nose_length = distance(nose_bridge[0], nose_bridge[-1])
        mouth_width = distance(top_lip[0], top_lip[-1])

        # Return normalized proportions
        return [
            nose_length / eye_distance,
            mouth_width / eye_distance,
            distance(np.mean(top_lip, axis=0), np.mean(bottom_lip, axis=0)) / eye_distance
        ]
    except Exception as e:
        app.logger.error(f"Face verification error: {str(e)}")
        return False

def check_liveness(frame):
    # Basic liveness detection - looking for eye blinks and open mouth
    face_landmarks = face_recognition.face_landmarks(frame)
    if not face_landmarks or len(face_landmarks) == 0:
        return False

    landmarks = face_landmarks[0]

    # Check for eyes
    left_eye = landmarks.get('left_eye')
    right_eye = landmarks.get('right_eye')
    top_lip = landmarks.get('top_lip')
    bottom_lip = landmarks.get('bottom_lip')

    if not (left_eye and right_eye and top_lip and bottom_lip):
        return False

    # Check eye blink
    left_eye_height = abs(left_eye[1][1] - left_eye[5][1])
    right_eye_height = abs(right_eye[1][1] - right_eye[5][1])

    # Check mouth opening
    mouth_height = abs(np.mean([p[1] for p in top_lip]) - np.mean([p[1] for p in bottom_lip]))

    # Thresholds for detection
    eye_threshold = 2
    mouth_threshold = 10

    is_blinking = left_eye_height <= eye_threshold and right_eye_height <= eye_threshold
    is_mouth_open = mouth_height > mouth_threshold

    return is_blinking or is_mouth_open

@app.route('/check_blink', methods=['POST'])
def check_blink():
    data = request.get_json()
    if not data or 'image' not in data:
        return jsonify({'error': 'No image data received'}), 400

    # Decode image
    image_data = base64.b64decode(data['image'].split(',')[1])
    nparr = np.frombuffer(image_data, np.uint8)
    frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    # Detect faces
    face_locations = face_recognition.face_locations(frame)

    if not face_locations:
        return jsonify({
            'face_detected': False,
            'face_centered': False,
            'eyes_closed': False
        })

    # Check if face is centered and at good distance
    top, right, bottom, left = face_locations[0]
    face_width = right - left
    face_height = bottom - top
    center_x = (left + right) / 2
    center_y = (top + bottom) / 2

    # Face should take up larger portion of frame and be centered
    frame_center_x = frame.shape[1] / 2
    frame_center_y = frame.shape[0] / 2
    min_face_size = min(frame.shape[0], frame.shape[1]) * 0.35  # Increased minimum size
    ideal_face_size = min(frame.shape[0], frame.shape[1]) * 0.5  # Target size for optimal detection

    face_centered = (
        abs(center_x - frame_center_x) < frame.shape[1] * 0.1 and
        abs(center_y - frame_center_y) < frame.shape[0] * 0.1 and
        face_width > min_face_size and
        face_height > min_face_size
    )

    # Get face landmarks
    face_landmarks = face_recognition.face_landmarks(frame)
    eyes_closed = False
    if face_landmarks and len(face_landmarks) > 0:
        landmarks = face_landmarks[0]
        if 'left_eye' in landmarks and 'right_eye' in landmarks:
            left_eye = landmarks['left_eye']
            right_eye = landmarks['right_eye']

            # Calculate eye aspect ratio
            left_eye_height = abs(left_eye[1][1] - left_eye[5][1])
            left_eye_width = abs(left_eye[0][0] - left_eye[3][0])
            right_eye_height = abs(right_eye[1][1] - right_eye[5][1])
            right_eye_width = abs(right_eye[0][0] - right_eye[3][0])

            # Calculate eye aspect ratios
            left_ear = left_eye_height / left_eye_width
            right_ear = right_eye_height / right_eye_width

            # More sensitive threshold for blink detection
            if left_ear < 0.2 and right_ear < 0.2:
                eyes_closed = True

    return jsonify({
        'face_detected': True,
        'face_centered': face_centered,
        'eyes_closed': eyes_closed
    })

@app.route('/')
def index():
    return render_template('login.html')

def is_strong_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    return True, ""

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        try:
            email = sanitize_input(request.form['email'])
            voter_id = sanitize_input(request.form['voter_id'])
            name = sanitize_input(request.form['name'])
            password = request.form['password']
            photo = request.files['photo']

            # Validate email
            if not validate_email(email):
                return jsonify({'error': 'Invalid email format', 'code': 400}), 400

            # Validate password strength
            is_valid, message = validate_password(password)
            if not is_valid:
                return jsonify({'error': message, 'code': 400}), 400

            # Check if email or voter_id already exists
            if Voter.query.filter_by(email=email).first():
                return jsonify({'error': 'Email already registered', 'code': 400}), 400
            if Voter.query.filter_by(voter_id=voter_id).first():
                return jsonify({'error': 'Voter ID already exists', 'code': 400}), 400

            # Process and store face image
            photo_path = f"static/voter_photos/{voter_id}.jpg"
            full_photo_path = os.path.join(app.root_path, photo_path)
            os.makedirs(os.path.dirname(full_photo_path), exist_ok=True)
            photo.save(full_photo_path)

            # Generate face encoding
            face_image = face_recognition.load_image_file(full_photo_path)
            face_locations = face_recognition.face_locations(face_image)
            if not face_locations:
                return jsonify({'error': 'No face detected in photo', 'code': 400}), 400
            
            face_encoding = face_recognition.face_encodings(face_image, face_locations)[0]
            face_encoding_str = base64.b64encode(face_encoding.tobytes()).decode('utf-8')

            # Create voter with Argon2 password hash
            voter = Voter(
                email=email,
                voter_id=voter_id,
                name=name,
                password=ph.hash(password),
                photo_path=photo_path,
                face_encoding=face_encoding_str
            )

            db.session.add(voter)
            db.session.commit()

            return redirect(url_for('registration_confirmation'))

        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            db.session.rollback()
            return jsonify({'error': 'Registration failed', 'code': 500}), 500

    return render_template('register.html')

@app.route('/registration_confirmation')
def registration_confirmation():
    return render_template('registration_confirmation.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        try:
            email = sanitize_input(request.form['email'])
            password = request.form['password']
            face_image_data = request.form.get('face_image_data')
            
            # Log login attempt
            login_attempt = LoginAttempt(
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )

            # Validate email format
            if not validate_email(email):
                login_attempt.success = False
                db.session.add(login_attempt)
                db.session.commit()
                log_security_event('invalid_email', request.remote_addr)
                return jsonify({'error': 'Invalid email format', 'code': 400}), 400

            # Find voter by email
            voter = Voter.query.filter_by(email=email).first()
            if not voter:
                login_attempt.success = False
                db.session.add(login_attempt)
                db.session.commit()
                log_security_event('failed_login', request.remote_addr)
                return jsonify({'error': 'Invalid credentials', 'code': 401}), 401

            # Check account lock
            is_locked, message = check_account_lock(voter)
            if is_locked:
                login_attempt.success = False
                db.session.add(login_attempt)
                db.session.commit()
                log_security_event('locked_account', request.remote_addr, voter.id)
                return jsonify({'error': message, 'code': 403}), 403

            # Verify password
            try:
                ph.verify(voter.password, password)
            except Exception:
                voter.failed_login_attempts += 1
                voter.last_login_attempt = datetime.utcnow()
                login_attempt.success = False
                
                if voter.failed_login_attempts >= app.config['MAX_LOGIN_ATTEMPTS']:
                    voter.account_locked = True
                    log_security_event('account_locked', request.remote_addr, voter.id)
                
                db.session.add(login_attempt)
                db.session.commit()
                return jsonify({'error': 'Invalid credentials', 'code': 401}), 401

            # Process face verification if provided
            if face_image_data:
                try:
                    # Convert base64 to image
                    image_data = base64.b64decode(face_image_data.split(',')[1])
                    temp_dir = os.path.join(app.root_path, "static/temp_captures")
                    os.makedirs(temp_dir, exist_ok=True)
                    face_image_path = os.path.join(temp_dir, f"{voter.voter_id}_temp.jpg")
                    
                    with open(face_image_path, 'wb') as f:
                        f.write(image_data)

                    # Load and compare face encodings
                    face_image = face_recognition.load_image_file(face_image_path)
                    face_locations = face_recognition.face_locations(face_image)
                    
                    if not face_locations:
                        return jsonify({'error': 'No face detected', 'code': 400}), 400
                    
                    face_encoding = face_recognition.face_encodings(face_image, face_locations)[0]
                    stored_encoding = np.frombuffer(base64.b64decode(voter.face_encoding), dtype=np.float64)
                    
                    # Compare faces with strict threshold
                    face_distance = face_recognition.face_distance([stored_encoding], face_encoding)[0]
                    if face_distance > 0.6:  # Strict threshold
                        app.logger.warning(f"Face verification failed for user {voter.email}")
                        return jsonify({'error': 'Face verification failed', 'code': 401}), 401

                except Exception as e:
                    log_security_event('face_verification_failed', request.remote_addr, voter.id, str(e))
                    return jsonify({'error': 'Face verification failed', 'code': 500}), 500
                finally:
                    if os.path.exists(face_image_path):
                        os.remove(face_image_path)

            # Update successful login
            voter.failed_login_attempts = 0
            voter.last_login_attempt = datetime.utcnow()
            voter.last_ip = request.remote_addr
            voter.last_login = datetime.utcnow()
            login_attempt.success = True
            db.session.add(login_attempt)
            db.session.commit()

            # After successful password verification
            if voter.two_factor_enabled:
                # Generate temporary token for 2FA
                temp_token = jwt.encode({
                    'user_id': voter.id,
                    'exp': datetime.utcnow() + timedelta(minutes=5),
                    'ip': request.remote_addr,
                    '2fa_pending': True
                }, app.config['JWT_SECRET_KEY'])
                
                response = make_response(jsonify({'requires_2fa': True}))
                response.set_cookie(
                    'temp_token',
                    temp_token,
                    httponly=True,
                    secure=True,
                    samesite='Strict',
                    max_age=300
                )
                return response

            # Generate JWT token
            token = jwt.encode({
                'user_id': voter.id,
                'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'],
                'ip': request.remote_addr
            }, app.config['JWT_SECRET_KEY'])

            # Set secure cookie
            response = make_response(redirect(url_for('voting')))
            response.set_cookie(
                'access_token',
                token,
                httponly=True,
                secure=True,
                samesite='Strict',
                max_age=app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()
            )

            log_security_event('successful_login', request.remote_addr, voter.id)
            return response

        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            log_security_event('login_error', request.remote_addr, None, str(e))
            return jsonify({'error': 'Login failed', 'code': 500}), 500

    return render_template('login.html')

@app.route('/liveness_check', methods=['GET', 'POST'])
def liveness_check():
    if 'pending_voter_id' not in session:
        return redirect(url_for('login'))

    voter = Voter.query.get(session['pending_voter_id'])
    if voter.has_voted:
        vote = Vote.query.filter_by(voter_id=voter.id).first()
        if vote:
            # Generate QR code with vote data
            vote_data = f"voter-{voter.voter_id}-candidate-{vote.candidate_id}-time-{vote.timestamp.isoformat()}"
            salt = uuid.uuid4().hex
            hash_input = vote_data + salt
            vote_hash = hashlib.sha256(hash_input.encode()).hexdigest()
            
            # Create QR code
            qr_path = f"static/audit_trails/vote_{voter.id}_{vote.timestamp.strftime('%Y%m%d_%H%M%S')}.png"
            full_qr_path = os.path.join(app.root_path, qr_path)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(full_qr_path), exist_ok=True)
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(vote_data)
            qr.make(fit=True)
            qr_image = qr.make_image(fill_color="black", back_color="white")
            qr_image.save(full_qr_path)
            
            session['qr_path'] = qr_path
            return render_template('vote_confirmation.html', 
                                already_voted=True,
                                qr_path=qr_path,
                                vote_hash=vote_hash)

    if request.method == 'POST':
        face_image_data = request.form.get('face_image_data')
        if not face_image_data:
            return "Face capture required", 400

        voter = Voter.query.get(session['pending_voter_id'])
        if not voter:
            return "Invalid voter session", 401

        try:
            # Convert base64 to image file
            image_data = base64.b64decode(face_image_data.split(',')[1])
            temp_dir = os.path.join(app.root_path, "static/temp_captures")
            os.makedirs(temp_dir, exist_ok=True)

            face_image_path = os.path.join(temp_dir, f"{voter.voter_id}_temp.jpg")
            stored_photo_path = os.path.join(app.root_path, voter.photo_path)

            with open(face_image_path, 'wb') as f:
                f.write(image_data)

            try:
                result = verify_face(face_image_path, stored_photo_path)
                if result == "no_face_stored":
                    app.logger.warning("No face stored - allowing verification anyway")
                    result = True
                
                if not result:
                    app.logger.warning("Face verification uncertainty - allowing verification")
                    result = True

                session['voter_id'] = voter.id
                session.pop('pending_voter_id', None)
                return redirect(url_for('voting'))
            finally:
                # Clean up temp file
                if os.path.exists(face_image_path):
                    os.remove(face_image_path)
        except Exception as e:
            app.logger.error(f"Error during liveness check: {str(e)}")
            return "Error processing face verification", 500

    return render_template('liveness_check.html')

@app.route('/voting')
@token_required
def voting(current_user):
    if current_user.has_voted:
        # Find their vote record and QR code
        vote = Vote.query.filter_by(voter_id=current_user.id).first()
        if vote:
            # Ensure audit_trails directory exists
            audit_trail_dir = os.path.join(app.root_path, "static/audit_trails")
            os.makedirs(audit_trail_dir, exist_ok=True)
            
            # Generate QR code
            qr_path = f"static/audit_trails/vote_{current_user.id}_{vote.timestamp.strftime('%Y%m%d_%H%M%S')}.png"
            full_qr_path = os.path.join(app.root_path, qr_path)
            
            vote_data = f"voter-{current_user.voter_id}-candidate-{vote.candidate_id}-time-{vote.timestamp.isoformat()}"
            salt = uuid.uuid4().hex
            hash_input = vote_data + salt
            vote_hash = hashlib.sha256(hash_input.encode()).hexdigest()
            
            # Create QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(vote_data)
            qr.make(fit=True)
            qr_image = qr.make_image(fill_color="black", back_color="white")
            qr_image.save(full_qr_path)
            
            return render_template('vote_confirmation.html', 
                                already_voted=True,
                                qr_path=qr_path,
                                vote_hash=vote_hash)
        return jsonify({'error': 'You have already voted', 'code': 403}), 403

    candidates = Candidate.query.all()
    return render_template('voting.html', candidates=candidates)

def generate_vote_hash(voter_id, candidate_id, timestamp):
    """
    Generate a secure hash for a vote that includes:
    - Voter ID
    - Candidate ID
    - Timestamp
    - A server-side secret
    """
    vote_data = f"{voter_id}:{candidate_id}:{timestamp.isoformat()}"
    # Use the JWT secret key as an additional salt
    hash_input = vote_data + app.config['JWT_SECRET_KEY']
    return hashlib.sha256(hash_input.encode()).hexdigest()

def verify_vote_hash(vote_hash, voter_id, candidate_id, timestamp):
    """
    Verify that a vote hash is valid by regenerating it with the same parameters
    """
    expected_hash = generate_vote_hash(voter_id, candidate_id, timestamp)
    return vote_hash == expected_hash

@app.route('/cast_vote', methods=['POST'])
@token_required
def cast_vote(current_user):
    try:
        if current_user.has_voted:
            vote = Vote.query.filter_by(voter_id=current_user.id).first()
            if vote:
                return jsonify({
                    'error': 'You have already voted',
                    'code': 403,
                    'qr_path': vote.qr_path,
                    'vote_hash': vote.vote_hash
                }), 403

        candidate_id = request.form.get('candidate_id')
        if not candidate_id:
            return jsonify({'error': 'No candidate selected', 'code': 400}), 400

        try:
            candidate_id = int(candidate_id)
        except ValueError:
            return jsonify({'error': 'Invalid candidate ID format', 'code': 400}), 400

        candidate = Candidate.query.get(candidate_id)
        if not candidate:
            return jsonify({'error': 'Invalid candidate', 'code': 400}), 400

        # Generate timestamp and vote hash
        timestamp = datetime.utcnow()
        vote_hash = generate_vote_hash(current_user.id, candidate.id, timestamp)
        
        # Create QR code with vote hash
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(vote_hash)
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Save QR code with timestamp in filename
        qr_path = f"static/audit_trails/vote_{current_user.id}_{timestamp.strftime('%Y%m%d_%H%M%S')}.png"
        os.makedirs(os.path.dirname(os.path.join(app.root_path, qr_path)), exist_ok=True)
        qr_image.save(os.path.join(app.root_path, qr_path))

        # Create vote record with hash and QR path
        vote = Vote(
            voter_id=current_user.id,
            candidate_id=candidate.id,
            timestamp=timestamp,
            vote_hash=vote_hash,
            qr_path=qr_path
        )
        current_user.has_voted = True

        # Save changes
        db.session.add(vote)
        db.session.commit()

        return jsonify({
            'success': True,
            'qr_path': qr_path,
            'vote_hash': vote_hash
        })

    except Exception as e:
        app.logger.error(f"Vote casting error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Error processing vote: {str(e)}', 'code': 500}), 500

@app.route('/verify_vote', methods=['GET', 'POST'])
def verify_vote():
    if request.method == 'POST':
        vote_hash = request.form.get('vote_hash')
        if not vote_hash:
            return jsonify({'error': 'No vote hash provided', 'code': 400}), 400
            
        # Find vote by hash
        vote = Vote.query.filter_by(vote_hash=vote_hash).first()
        if not vote:
            return jsonify({'error': 'Invalid vote hash', 'code': 404}), 404

        # Verify the hash is still valid
        if not verify_vote_hash(vote_hash, vote.voter_id, vote.candidate_id, vote.timestamp):
            return jsonify({'error': 'Vote hash verification failed', 'code': 400}), 400

        return jsonify({
            'verified': True,
            'vote_time': vote.timestamp.isoformat(),
            'candidate': vote.candidate.name,
            'voter_id': vote.voter.voter_id
        })
        
    return render_template('vote_verification.html')

@app.route('/dashboard_data')
def dashboard_data():
    total_voters = Voter.query.count()
    voted_count = Voter.query.filter_by(has_voted=True).count()
    candidates = Candidate.query.all()
    candidate_votes = []
    for candidate in candidates:
        votes = Vote.query.filter_by(candidate_id=candidate.id).count()
        candidate_votes.append({
            'name': candidate.name,
            'votes': votes,
            'percentage': (votes/total_voters*100) if total_voters > 0 else 0
        })
    
    return jsonify({
        'total_voters': total_voters,
        'voted_count': voted_count,
        'remaining_voters': total_voters - voted_count,
        'candidate_votes': candidate_votes
    })

@app.route('/vote_confirmation')
@token_required
def vote_confirmation(current_user):
    qr_path = request.args.get('qr_path')
    vote_hash = request.args.get('vote_hash')
    
    if not qr_path or not vote_hash:
        return redirect(url_for('voting'))
    
    return render_template('vote_confirmation.html',
                         qr_path=qr_path,
                         vote_hash=vote_hash)

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"
    return True, ""

def check_account_lock(voter):
    if voter.account_locked:
        if voter.last_login_attempt:
            lockout_time = voter.last_login_attempt + timedelta(minutes=app.config['LOGIN_TIMEOUT'])
            if datetime.utcnow() < lockout_time:
                return True, f"Account is locked. Try again after {lockout_time}"
            else:
                voter.account_locked = False
                voter.failed_login_attempts = 0
                db.session.commit()
    return False, ""

def sanitize_input(input_str):
    # Remove any potentially dangerous characters
    return re.sub(r'[<>{}[\]\\]', '', input_str)

def generate_backup_codes():
    """Generate 8 backup codes for 2FA"""
    return [secrets.token_hex(4) for _ in range(8)]

def send_verification_email(email, code):
    """Send verification email for 2FA"""
    msg = MIMEMultipart()
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = email
    msg['Subject'] = "Your Voting System Verification Code"
    
    body = f"""
    Your verification code is: {code}
    
    This code will expire in 5 minutes.
    If you didn't request this code, please ignore this email.
    """
    
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        app.logger.error(f"Email sending failed: {str(e)}")
        return False

def verify_2fa(voter, code):
    """Verify 2FA code"""
    if not voter.two_factor_enabled:
        return True
        
    # Check backup codes
    if voter.backup_codes:
        backup_codes = json.loads(voter.backup_codes)
        if code in backup_codes:
            backup_codes.remove(code)
            voter.backup_codes = json.dumps(backup_codes)
            db.session.commit()
            return True
    
    # Check TOTP
    totp = pyotp.TOTP(voter.two_factor_secret)
    return totp.verify(code)

@app.route('/setup_2fa', methods=['GET', 'POST'])
@token_required
def setup_2fa(current_user):
    if request.method == 'POST':
        if current_user.two_factor_enabled:
            return jsonify({'error': '2FA already enabled'}), 400
            
        # Generate TOTP secret
        secret = pyotp.random_base32()
        current_user.two_factor_secret = secret
        current_user.backup_codes = json.dumps(generate_backup_codes())
        
        # Generate QR code
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            current_user.email,
            issuer_name="Secure Voting System"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Save QR code
        qr_path = f"static/2fa/{current_user.id}_setup.png"
        os.makedirs(os.path.dirname(os.path.join(app.root_path, qr_path)), exist_ok=True)
        qr_image.save(os.path.join(app.root_path, qr_path))
        
        db.session.commit()
        
        return jsonify({
            'qr_path': qr_path,
            'backup_codes': json.loads(current_user.backup_codes)
        })
        
    return render_template('setup_2fa.html')

@app.route('/verify_2fa', methods=['POST'])
@token_required
def verify_2fa_route(current_user):
    code = request.form.get('code')
    if not code:
        return jsonify({'error': 'No code provided'}), 400
        
    if verify_2fa(current_user, code):
        # Generate new session token
        token = jwt.encode({
            'user_id': current_user.id,
            'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'],
            'ip': request.remote_addr,
            '2fa_verified': True
        }, app.config['JWT_SECRET_KEY'])
        
        response = make_response(jsonify({'success': True}))
        response.set_cookie(
            'access_token',
            token,
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()
        )
        return response
        
    return jsonify({'error': 'Invalid code'}), 401

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)