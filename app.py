from flask import Flask, render_template, request, redirect
import sqlite3

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect('database.db')
    return conn

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form['username']

        conn = get_db()
        conn.execute("INSERT INTO users (username) VALUES (?)", (user,))
        conn.commit()
        conn.close()

        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']

        conn = get_db()
        result = conn.execute("SELECT * FROM users WHERE username=?", (user,)).fetchone()
        conn.close()

        if result:
            return redirect('/dashboard')
        else:
            return "User not found 😢"
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/apply', methods=['GET', 'POST'])
def apply():
    if request.method == 'POST':
        username = request.form['username']
        full_name = request.form['full_name']

        conn = get_db()
        conn.execute(
            "INSERT INTO applications (username, full_name, status) VALUES (?, ?, ?)",
            (username, full_name, "Pending")
        )
        conn.commit()
        conn.close()

        return "Application submitted successfully "

    return render_template('apply.html')

@app.route('/status')
def status():
    conn = get_db()
    data = conn.execute("SELECT * FROM applications").fetchall()
    conn.close()

    return render_template('status.html', applications=data)

if __name__ == '__main__':
    app.run(debug=True)