from flask import Flask, request, render_template, redirect, url_for, flash, session
import sqlite3
import bcrypt
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'  

# Database setup
DATABASE = 'users.db'

def init_db():
    """Database-i users cədvəli ilə yaradır"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def get_db_connection():
    """Database bağlantısı əldə edir"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    """Ana səhifə - login səhifəsinə yönləndir"""
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """İstifadəçi qeydiyyatı"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        
        # Əsas yoxlama
        if not username or not email or not password:
            flash('Bütün sahələr doldurulmalıdır', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Şifrə ən azı 6 simvol olmalıdır', 'error')
            return render_template('register.html')
        
        # E-mail artıq mövcuddurmu yoxla
        conn = get_db_connection()
        existing_user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        
        if existing_user:
            flash('Bu e-mail artıq qeydiyyatdan keçib', 'error')
            conn.close()
            return render_template('register.html')
        
        # Şifrəni bcrypt ilə hash-la
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Yeni istifadəçi əlavə et
        try:
            conn.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                        (username, email, password_hash))
            conn.commit()
            flash('Qeydiyyat uğurla tamamlandı! İndi giriş edə bilərsiniz.', 'success')
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash('Qeydiyyat zamanı xəta baş verdi', 'error')
            conn.close()
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """İstifadəçi girişi"""
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        
        if not email or not password:
            flash('E-mail və şifrə daxil edilməlidir', 'error')
            return render_template('login.html')
        
        # İstifadəçini database-dən əldə et
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        # İstifadəçi və şifrəni yoxla
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            # Uğurlu giriş
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            # Təhlükəsizlik üçün ümumi xəta mesajı
            flash('E-mail və ya şifrə yanlışdır', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard səhifəsi - yalnız uğurlu girişdən sonra görünür"""
    if not session.get('logged_in'):
        flash('Dashboard-a giriş üçün əvvəlcə daxil olmalısınız', 'error')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/logout')
def logout():
    """İstifadəçi çıxışı"""
    session.clear()
    flash('Uğurla çıxış etdiniz', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
