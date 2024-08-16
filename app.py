from flask import Flask, render_template, request, redirect, url_for, jsonify, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
from werkzeug.utils import secure_filename
from functools import wraps
from pymongo import MongoClient
from bson.objectid import ObjectId

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Connect to MongoDB
client = MongoClient('mongodb://root:example@localhost:27017/')
db = client['your_database_name']

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/new/login'

# User model and functions for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username, password_hash):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(user_id=str(user_data['_id']), username=user_data['username'], password_hash=user_data['password'])
    return None

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        if not api_key:
            abort(401, description="Unauthorized access")
        key = db.api_keys.find_one({'key': api_key, 'active': True})
        if not key:
            abort(401, description="Unauthorized access")
        return f(*args, **kwargs)
    return decorated_function

@app.route('/new/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = db.users.find_one({'username': username})
        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_id=str(user_data['_id']), username=user_data['username'], password_hash=user_data['password'])
            login_user(user)
            return redirect(url_for('index'))
    return render_template('new/login.html')

@app.route('/new/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = db.users.find_one({'username': username})
        if existing_user:
            return render_template('new/register.html', error="Username already exists. Please choose a different username.")

        hashed_password = generate_password_hash(password, method='sha256')
        user_id = db.users.insert_one({'username': username, 'password': hashed_password}).inserted_id
        return redirect(url_for('login'))
    
    return render_template('new/register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('new/index.html')

@app.route('/generate', methods=['POST'])
@login_required
def generate():
    description = request.form['description']
    key = secrets.token_hex(16)
    db.api_keys.insert_one({
        'user_id': ObjectId(current_user.id),
        'key': key,
        'description': description,
        'active': True
    })
    return redirect(url_for('index'))

@app.route('/keys')
@login_required
def keys():
    user_keys = db.api_keys.find({'user_id': ObjectId(current_user.id)})
    keys_dict = {key['key']: {'description': key['description'], 'active': key['active']} for key in user_keys}
    return jsonify(keys_dict)

@app.route('/deactivate', methods=['POST'])
@login_required
def deactivate():
    api_key = request.form['key']
    result = db.api_keys.update_one({'key': api_key, 'user_id': ObjectId(current_user.id)}, {'$set': {'active': False}})
    if result.matched_count > 0:
        return redirect(url_for('index'))
    else:
        return 'API key not found or you do not have permission to deactivate this key.', 404

@app.route('/api/upload', methods=['POST'])
@require_api_key
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        db.stored_files.insert_one({
            'user_id': ObjectId(current_user.id),
            'filename': filename,
            'file_path': file_path
        })
        return 'File uploaded successfully', 200
    return 'File type not allowed', 400

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
