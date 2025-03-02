from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

@app.route('/user', methods=['GET'])
def get_user():
    # Vulnerable to SQL injection:
    # User input is directly concatenated into the SQL query.
    user_id = request.args.get('id', '')
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    try:
        cursor.execute(query)
        result = cursor.fetchone()
    except Exception as e:
        result = str(e)
    conn.close()
    return jsonify({'result': result})

@app.route('/exec', methods=['GET'])
def exec_command():
    # Vulnerable to command injection:
    # User input is executed as a system command without sanitization.
    command = request.args.get('cmd', '')
    output = os.popen(command).read()
    return jsonify({'output': output})

if __name__ == '__main__':
    # Setup: Create a test database with a simple table and data.
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)')
    cursor.execute("INSERT INTO users (name) VALUES ('Alice')")
    cursor.execute("INSERT INTO users (name) VALUES ('Bob')")
    conn.commit()
    conn.close()
    
    app.run(debug=True)
