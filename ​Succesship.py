from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
import re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///complex_crud.db'
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Change this in production for security
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Models

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # user/admin

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def json(self):
        return {'id': self.id, 'username': self.username, 'email': self.email, 'role': self.role}

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    operation = db.Column(db.String(10), nullable=False)  # CREATE, READ, UPDATE, DELETE
    target_table = db.Column(db.String(50), nullable=False)
    target_id = db.Column(db.Integer, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    old_data = db.Column(db.Text)
    new_data = db.Column(db.Text)

class Record(db.Model):
    __tablename__ = 'records'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    contact = db.Column(db.String(20), nullable=False)

    def json(self):
        return {'id': self.id, 'name': self.name, 'contact': self.contact}

db.create_all()

# Helper Functions

def log_audit(user_id, operation, table, target_id=None, old_data=None, new_data=None):
    audit = AuditLog(
        user_id=user_id,
        operation=operation,
        target_table=table,
        target_id=target_id,
        old_data=old_data,
        new_data=new_data,
    )
    db.session.add(audit)
    db.session.commit()

def validate_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def is_admin():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return user and user.role == 'admin'

# Authentication Routes

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not (data.get('username') and data.get('email') and data.get('password')):
        return jsonify({"error": "Missing fields"}), 400
    if not validate_email(data['email']):
        return jsonify({"error": "Invalid email format"}), 400
    if User.query.filter((User.username == data['username']) | (User.email == data['email'])).first():
        return jsonify({"error": "User already exists"}), 409
    user = User(username=data['username'], email=data['email'], role='user')
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "User registered"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if user and user.check_password(data.get('password')):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify({"error": "Invalid credentials"}), 401

# CRUD API with Auth & Audit

@app.route('/records', methods=['POST'])
@jwt_required()
def create_record():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json()
    if not (data.get('name') and data.get('contact')):
        return jsonify({"error": "Missing fields"}), 400
    record = Record(name=data['name'], contact=data['contact'])
    db.session.add(record)
    db.session.commit()
    log_audit(user_id=get_jwt_identity(), operation="CREATE", table="records", target_id=record.id, new_data=str(record.json()))
    return jsonify(record.json()), 201

@app.route('/records', methods=['GET'])
@jwt_required()
def list_records():
    # Pagination & filtering example
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    search = request.args.get('search', '')
    query = Record.query
    if search:
        query = query.filter(Record.name.contains(search))
    pagination = query.paginate(page, per_page, error_out=False)
    data = [r.json() for r in pagination.items]
    log_audit(user_id=get_jwt_identity(), operation="READ", table="records")
    return jsonify({
        'data': data,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': pagination.page
    })

@app.route('/records/<int:id>', methods=['GET'])
@jwt_required()
def get_record(id):
    record = Record.query.get(id)
    if not record:
        return jsonify({"error": "Record not found"}), 404
    log_audit(user_id=get_jwt_identity(), operation="READ", table="records", target_id=id)
    return jsonify(record.json())

@app.route('/records/<int:id>', methods=['PUT'])
@jwt_required()
def update_record(id):
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    record = Record.query.get(id)
    if not record:
        return jsonify({"error": "Record not found"}), 404

    old_data = str(record.json())
    data = request.get_json()
    if not (data.get('name') and data.get('contact')):
        return jsonify({"error": "Missing fields"}), 400

    record.name = data['name']
    record.contact = data['contact']
    db.session.commit()
    new_data = str(record.json())
    log_audit(user_id=get_jwt_identity(), operation="UPDATE", table="records", target_id=id, old_data=old_data, new_data=new_data)
    return jsonify(record.json())

@app.route('/records/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_record(id):
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    record = Record.query.get(id)
    if not record:
        return jsonify({"error": "Record not found"}), 404
    old_data = str(record.json())
    db.session.delete(record)
    db.session.commit()
    log_audit(user_id=get_jwt_identity(), operation="DELETE", table="records", target_id=id, old_data=old_data)
    return jsonify({"msg": "Record deleted"})

# Bulk delete example
@app.route('/records/bulk_delete', methods=['POST'])
@jwt_required()
def bulk_delete():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json()
    ids = data.get('ids', [])
    if not ids or not isinstance(ids, list):
        return jsonify({"error": "Invalid IDs"}), 400
    for record_id in ids:
        record = Record.query.get(record_id)
        if record:
            old_data = str(record.json())
            db.session.delete(record)
            log_audit(user_id=get_jwt_identity(), operation="DELETE", table="records", target_id=record_id, old_data=old_data)
    db.session.commit()
    return jsonify({"msg": "Bulk delete completed"})

if __name__ == '__main__':
    app.run(debug=True)
