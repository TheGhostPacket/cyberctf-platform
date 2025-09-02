# app.py - Main Flask Application
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import hashlib
import base64
import os
from datetime import datetime
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Database initialization
def init_db():
    conn = sqlite3.connect('ctf.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            total_score INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Challenges table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            points INTEGER NOT NULL,
            flag TEXT NOT NULL,
            hint TEXT,
            challenge_data TEXT
        )
    ''')
    
    # Submissions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            challenge_id INTEGER,
            submitted_flag TEXT,
            is_correct BOOLEAN,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (challenge_id) REFERENCES challenges (id)
        )
    ''')
    
    # Insert sample challenges
    challenges = [
        {
            'title': 'Basic Flag Hunt',
            'description': 'Find the hidden flag in this HTML source code: &lt;!-- FLAG{welcome_to_ctf} --&gt;',
            'category': 'Web Security',
            'points': 100,
            'flag': 'FLAG{welcome_to_ctf}',
            'hint': 'Check the HTML source code comments',
            'challenge_data': '<!-- FLAG{welcome_to_ctf} -->'
        },
        {
            'title': 'Caesar Cipher',
            'description': 'Decode this Caesar cipher (shift 13): SYNT{PELCGB_VF_SHA}',
            'category': 'Cryptography',
            'points': 150,
            'flag': 'FLAG{CRYPTO_IS_FUN}',
            'hint': 'ROT13 cipher - shift each letter 13 positions',
            'challenge_data': 'SYNT{PELCGB_VF_SHA}'
        },
        {
            'title': 'Base64 Decoder',
            'description': 'Decode this Base64 string: RkxBR3tiYXNlNjRfZGVjb2Rpbmd9',
            'category': 'Cryptography', 
            'points': 120,
            'flag': 'FLAG{base64_decoding}',
            'hint': 'Use Base64 decoding',
            'challenge_data': 'RkxBR3tiYXNlNjRfZGVjb2Rpbmd9'
        },
        {
            'title': 'Weak Password',
            'description': 'This MD5 hash represents a common password: 5d41402abc4b2a76b9719d911017c592',
            'category': 'Password Cracking',
            'points': 200,
            'flag': 'FLAG{hello}',
            'hint': 'Try common passwords like hello, world, password, etc.',
            'challenge_data': '5d41402abc4b2a76b9719d911017c592'
        },
        {
            'title': 'SQL Injection',
            'description': 'Find the flag by bypassing this login: Username: admin, Password: ?',
            'category': 'Web Security',
            'points': 250,
            'flag': 'FLAG{sql_injection_master}',
            'hint': 'Try SQL injection in the password field: \' OR \'1\'=\'1\' --',
            'challenge_data': 'SELECT * FROM users WHERE username=\'admin\' AND password=\'[YOUR_INPUT]\''
        },
        {
            'title': 'Network Analysis',
            'description': 'What protocol typically uses port 443?',
            'category': 'Network Security',
            'points': 100,
            'flag': 'FLAG{HTTPS}',
            'hint': 'Think about secure web traffic',
            'challenge_data': 'Port 443 is commonly used for...'
        },
        {
            'title': 'Binary Analysis',
            'description': 'Convert this binary to ASCII: 01000110 01001100 01000001 01000111 01111011 01100010 01101001 01101110 01100001 01110010 01111001 01111101',
            'category': 'Reverse Engineering',
            'points': 180,
            'flag': 'FLAG{binary}',
            'hint': 'Convert each 8-bit binary number to its ASCII character',
            'challenge_data': '01000110 01001100 01000001 01000111 01111011 01100010 01101001 01101110 01100001 01110010 01111001 01111101'
        }
    ]
    
    # Insert challenges if they don't exist
    for challenge in challenges:
        cursor.execute('SELECT id FROM challenges WHERE title = ?', (challenge['title'],))
        if not cursor.fetchone():
            cursor.execute('''
                INSERT INTO challenges (title, description, category, points, flag, hint, challenge_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (challenge['title'], challenge['description'], challenge['category'], 
                  challenge['points'], challenge['flag'], challenge['hint'], challenge['challenge_data']))
    
    conn.commit()
    conn.close()

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'})
        
        password_hash = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('ctf.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                          (username, email, password_hash))
            conn.commit()
            conn.close()
            return jsonify({'success': 'Registration successful! Please login.'})
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username or email already exists'})
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('ctf.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            return jsonify({'success': 'Login successful!'})
        else:
            return jsonify({'error': 'Invalid username or password'})
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('ctf.db')
    cursor = conn.cursor()
    
    # Get user stats
    cursor.execute('SELECT total_score FROM users WHERE id = ?', (session['user_id'],))
    user_score = cursor.fetchone()[0]
    
    # Get challenges by category
    cursor.execute('SELECT DISTINCT category FROM challenges')
    categories = [row[0] for row in cursor.fetchall()]
    
    # Get solved challenges
    cursor.execute('''
        SELECT challenge_id FROM submissions 
        WHERE user_id = ? AND is_correct = 1
    ''', (session['user_id'],))
    solved_challenges = [row[0] for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template('dashboard.html', 
                         username=session['username'],
                         user_score=user_score,
                         categories=categories,
                         solved_count=len(solved_challenges))

@app.route('/challenges/<category>')
def challenges(category):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('ctf.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, title, description, points, hint FROM challenges WHERE category = ?', (category,))
    challenges = cursor.fetchall()
    
    # Get solved challenges
    cursor.execute('''
        SELECT challenge_id FROM submissions 
        WHERE user_id = ? AND is_correct = 1
    ''', (session['user_id'],))
    solved_challenges = [row[0] for row in cursor.fetchall()]
    
    conn.close()
    
    challenges_data = []
    for challenge in challenges:
        challenges_data.append({
            'id': challenge[0],
            'title': challenge[1],
            'description': challenge[2],
            'points': challenge[3],
            'hint': challenge[4],
            'solved': challenge[0] in solved_challenges
        })
    
    return render_template('challenges.html', 
                         category=category, 
                         challenges=challenges_data)

@app.route('/submit_flag', methods=['POST'])
def submit_flag():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'})
    
    challenge_id = request.form['challenge_id']
    submitted_flag = request.form['flag'].strip()
    
    conn = sqlite3.connect('ctf.db')
    cursor = conn.cursor()
    
    # Check if already solved
    cursor.execute('''
        SELECT id FROM submissions 
        WHERE user_id = ? AND challenge_id = ? AND is_correct = 1
    ''', (session['user_id'], challenge_id))
    
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Challenge already solved!'})
    
    # Get correct flag
    cursor.execute('SELECT flag, points FROM challenges WHERE id = ?', (challenge_id,))
    challenge = cursor.fetchone()
    
    if not challenge:
        conn.close()
        return jsonify({'error': 'Challenge not found'})
    
    correct_flag, points = challenge
    is_correct = submitted_flag == correct_flag
    
    # Record submission
    cursor.execute('''
        INSERT INTO submissions (user_id, challenge_id, submitted_flag, is_correct)
        VALUES (?, ?, ?, ?)
    ''', (session['user_id'], challenge_id, submitted_flag, is_correct))
    
    if is_correct:
        # Update user score
        cursor.execute('''
            UPDATE users SET total_score = total_score + ? WHERE id = ?
        ''', (points, session['user_id']))
    
    conn.commit()
    conn.close()
    
    if is_correct:
        return jsonify({'success': f'Correct! You earned {points} points!'})
    else:
        return jsonify({'error': 'Incorrect flag. Try again!'})

@app.route('/leaderboard')
def leaderboard():
    conn = sqlite3.connect('ctf.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT username, total_score, 
               (SELECT COUNT(*) FROM submissions 
                WHERE user_id = users.id AND is_correct = 1) as solved_count
        FROM users 
        ORDER BY total_score DESC 
        LIMIT 50
    ''')
    
    leaderboard_data = cursor.fetchall()
    conn.close()
    
    return render_template('leaderboard.html', leaderboard=leaderboard_data)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)