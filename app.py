from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_migrate import Migrate
import secrets
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

secure_key = secrets.token_hex(16)
app.config['JWT_SECRET_KEY'] = secure_key # To be changed to a secure random key in production

db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)
migrate = Migrate(app, db)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Todo model
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create the database tables
with app.app_context():
    db.create_all()

# Helper function to serialize Todo objects
def todo_to_dict(todo):
    return {"id": todo.id, "task": todo.task, "completed": todo.completed, "user_id": todo.user_id}

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Username and password are required"}), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "Username already exists"}), 400
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({"error": "Invalid username or password"}), 401
    access_token = create_access_token(identity=str(user.id))
    return jsonify(access_token=access_token)

# CREATE a new todo (protected)
@app.route('/todos', methods=['POST'])
@jwt_required()
def create_todo():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    if not data or 'task' not in data:
        return jsonify({"error": "Task is required"}), 400
    new_todo = Todo(task=data['task'], completed=False, user_id=user_id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify(todo_to_dict(new_todo)), 201

# READ all todos (protected)
@app.route('/todos', methods=['GET'])
@jwt_required()
def get_todos():
    user_id = int(get_jwt_identity())
    todos = Todo.query.filter_by(user_id=user_id).all()
    return jsonify([todo_to_dict(todo) for todo in todos])

# READ a single todo (protected)
@app.route('/todos/<int:id>', methods=['GET'])
@jwt_required()
def get_todo(id):
    user_id = int(get_jwt_identity())
    todo = Todo.query.filter_by(id=id, user_id=user_id).first_or_404()
    return jsonify(todo_to_dict(todo))

# UPDATE a todo (protected)
@app.route('/todos/<int:id>', methods=['PUT'])
@jwt_required()
def update_todo(id):
    user_id = int(get_jwt_identity())
    todo = Todo.query.filter_by(id=id, user_id=user_id).first_or_404(id)
    data = request.get_json()
    if 'task' in data:
        todo.task = data['task']
    if 'completed' in data:
        todo.completed = data['completed']
    db.session.commit()
    return jsonify(todo_to_dict(todo))

# DELETE a todo (protected)
@app.route('/todos/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_todo(id):
    user_id = int(get_jwt_identity())
    todo = Todo.query.filter_by(id=id, user_id=user_id).first_or_404(id)
    db.session.delete(todo)
    db.session.commit()
    return '', 204

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)