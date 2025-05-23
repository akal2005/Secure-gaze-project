import os      
import json
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from flask import send_from_directory

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Configuration for file uploads
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Character-to-color mapping for graphical password
CHARACTERS = list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
COLORS = [
    '#FF0000', '#00FF00', '#0000FF', '#FFFF00', '#FF00FF', '#00FFFF',
    '#FFA500', '#800080', '#008000', '#FFC0CB', '#A52A2A', '#FFD700',
    '#FF4500', '#DA70D6', '#7FFF00', '#4682B4', '#FF69B4', '#9ACD32',
    '#20B2AA', '#9932CC', '#FFDAB9', '#00CED1', '#FF6347', '#ADFF2F',
    '#BA55D3', '#98FB98', '#F08080', '#7B68EE', '#FFE4B5', '#40E0D0',
    '#C71585', '#66CDAA', '#FFDEAD', '#00FA9A', '#DC143C', '#F0E68C',
    '#6495ED', '#FFF0F5', '#228B22', '#DAA520', '#6A5ACD', '#F5DEB3',
    '#4169E1', '#FA8072', '#2E8B57', '#EEE8AA', '#B22222', '#87CEEB',
    '#9400D3', '#F4A460', '#6B8E23', '#FFB6C1', '#483D8B', '#FF8C00',
    '#90EE90', '#BC8F8F', '#8B008B', '#556B2F', '#FFEBCD', '#1E90FF',
    '#FFFACD', '#D2691E'
]  # 62 distinct colors
CHAR_TO_COLOR = dict(zip(CHARACTERS, COLORS))
COLOR_TO_CHAR = dict(zip(COLORS, CHARACTERS))

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT,
            bio TEXT,
            profile_pic TEXT,
            graphical_password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        graphical_password = request.form.get('graphical_password', '')
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if not user:
            flash('Invalid username', 'danger')
            return render_template('login.html')
        
        # Validate graphical password
        if not graphical_password:
            flash('Graphical password required', 'danger')
            return render_template('login.html')
        
        try:
            color_pairs = json.loads(graphical_password)  # e.g., [['#FF0000', '#00FF00'], ...]
            char_password = ''
            for inner_color, outer_color in color_pairs:
                inner_char = COLOR_TO_CHAR.get(inner_color)
                outer_char = COLOR_TO_CHAR.get(outer_color)
                if not (inner_char and outer_char):
                    flash('Invalid color selection in graphical password', 'danger')
                    return render_template('login.html')
                char_password += inner_char + outer_char
            if not check_password_hash(user['graphical_password'], char_password):
                flash('Invalid graphical password', 'danger')
                return render_template('login.html')
        except (json.JSONDecodeError, KeyError):
            flash('Invalid graphical password format', 'danger')
            return render_template('login.html')
        
        # Successful login
        session['user_id'] = user['id']
        session['username'] = user['username']
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        full_name = request.form.get('full_name', '')
        graphical_password = request.form.get('graphical_password', '')
        
        # Validate graphical password
        if not graphical_password:
            flash('Graphical password required', 'danger')
            return render_template('register.html')
        
        try:
            color_pairs = json.loads(graphical_password)
            char_password = ''
            for inner_color, outer_color in color_pairs:
                inner_char = COLOR_TO_CHAR.get(inner_color)
                outer_char = COLOR_TO_CHAR.get(outer_color)
                if not (inner_char and outer_char):
                    flash('Invalid color selection in graphical password', 'danger')
                    return render_template('register.html')
                char_password += inner_char + outer_char
            if not char_password:
                flash('Graphical password cannot be empty', 'danger')
                return render_template('register.html')
            hashed_graphical_password = generate_password_hash(char_password)
        except (json.JSONDecodeError, KeyError):
            flash('Invalid graphical password format', 'danger')
            return render_template('register.html')
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, email, full_name, graphical_password) VALUES (?, ?, ?, ?)',
                         (username, email, full_name, hashed_graphical_password))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template('dashboard.html', user=user)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        full_name = request.form.get('full_name', '')
        bio = request.form.get('bio', '')
        
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"user_{session['user_id']}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                old_pic = conn.execute('SELECT profile_pic FROM users WHERE id = ?', 
                                      (session['user_id'],)).fetchone()['profile_pic']
                if old_pic and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], old_pic)):
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], old_pic))
                
                conn.execute('UPDATE users SET profile_pic = ? WHERE id = ?', 
                           (filename, session['user_id']))
        
        conn.execute('UPDATE users SET full_name = ?, bio = ? WHERE id = ?', 
                    (full_name, bio, session['user_id']))
        conn.commit()
        flash('Profile updated successfully!', 'success')
    
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template('profile.html', user=user)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/graphical_password')
def graphical_password():
    return render_template('graphical_password.html')

if __name__ == '__main__':
    app.run(debug=True)