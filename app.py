from flask import Flask, render_template, request, jsonify, render_template_string, make_response
import mysql.connector
import requests
import jwt
import os
import base64
import json
import secrets
import os
import shlex
import subprocess
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# Database connection details
host = 'localhost'  # Update with your host
user = 'root'       # Update with your username
password = 'root'   # Update with your password

# Establishing the connection
conn = mysql.connector.connect(
    host=host,
    user=user,
    password=password
)

try:
    if conn.is_connected():
        print('Connected to MySQL database')
        cursor = conn.cursor()

        # Create and use the database
        cursor.execute("CREATE DATABASE IF NOT EXISTS rest_apisec;")
        cursor.execute("USE rest_apisec;")

        # Create the rest_user table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rest_user (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                role VARCHAR(255) NOT NULL
            );
        """)

        # Insert sample data into rest_user
        cursor.execute("""
            INSERT INTO rest_user (name, password, email, role) VALUES
                ('user', '1rdTeqlm2g', 'user@mail.com', 'user'),
                ('admin', '9yRyb5P9k7', 'admin@mail.com', 'admin');
        """)

        # Add 'DESCRIPTION' column to 'rest_user' table
        cursor.execute("ALTER TABLE rest_user ADD COLUMN DESCRIPTION VARCHAR(255);")

        # Add 'api_key' column to 'rest_user' table
        cursor.execute("ALTER TABLE rest_user ADD COLUMN api_key VARCHAR(16);")

        # Update 'api_key' with random 16-bit key for existing users
        cursor.execute("UPDATE rest_user SET api_key = SUBSTRING(MD5(RAND()), 1, 16);")

        # Display the updated table structure
        cursor.execute("DESCRIBE rest_user;")
        print("Table structure for 'rest_user':")
        for row in cursor.fetchall():
            print(row)

        # Create the old_db table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS old_db (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                admin INT DEFAULT 1,
                api_key VARCHAR(32) DEFAULT NULL,
                chat VARCHAR(255) DEFAULT NULL
            );
        """)

        # Insert sample data into old_db
        cursor.execute("""
            INSERT INTO old_db (username, password, email, admin, api_key, chat)
            VALUES
                ('admin', '404mJX6ez3', 'admin@mail.com', 0, '7N6X50Ev14WcoX851023x4242pW10IyT', 'I am admin user'),
                ('user', 'U4gOSJ7OS9', 'user@mail.com', 1, 'pgO3Lo4MqQiK6Mg0w0k587O258d47FaE', 'I am a normal user');
        """)

        # Add 'session' column to 'old_db' table
        cursor.execute("ALTER TABLE old_db ADD COLUMN session VARCHAR(255);")

        print("Script executed successfully.")

except mysql.connector.Error as err:
    print(f"Error: {err}")

finally:
    if conn.is_connected():
        cursor.close()
        conn.close()
        print('MySQL connection is closed')



# Initialize Flask app
app = Flask(__name__)

# Secret key for JWT
secret_key = 'jwt'

# MySQL Configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'rest_apisec',
    'auth_plugin': 'mysql_native_password'
}

# Function to create a MySQL connection
def create_connection():
    return mysql.connector.connect(**db_config)

# Function to generate JWT token
def generate_token(user_id, name):
    payload = {
        'user_id': user_id,
        'name': name,
        'exp': datetime.utcnow() + timedelta(days=1)
    }
    return jwt.encode(payload, secret_key, algorithm='HS256')

# Route for the main page
@app.route('/')
def main_page():
    return render_template('main.html')

# New API2 endpoint
@app.route('/api2')
def api2():
    return ('Cannot GET /'), 404

# API2 user endpoint
@app.route('/api2/user')
def api2_user():
    return jsonify({'message': 'Welcome to Vuln-REST'}), 200


# Register endpoint
@app.route('/api2/user/register', methods=['POST'])
def api2_register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role', 'user')  # Default role is 'user'

    try:
        connection = create_connection()
        cursor = connection.cursor()

        # Check if the username already exists
        cursor.execute('SELECT * FROM rest_user WHERE name = %s', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({'error': 'User already exists'}), 400

        # Insert user data into the rest_user table
        cursor.execute('INSERT INTO rest_user (name, password, email, role) VALUES (%s, %s, %s, %s)',
                       (username, password, email, role))
        connection.commit()

        return jsonify({'message': 'Registration successful'}), 201
    except Exception as e:
        print(e)
        return jsonify({'error': 'Registration failed'}), 500
    finally:
        if connection:
            connection.close()

# Login endpoint
@app.route('/api2/user/login', methods=['POST', 'GET'])
def api2_login():
    if request.method == 'GET':
        return jsonify({'message': 'Please enter username and password'}), 400

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        # Check if the user exists in the rest_user table
        cursor.execute('SELECT * FROM rest_user WHERE name = %s', (username,))
        user = cursor.fetchone()

        if user:
            # Check if the provided password is correct
            if user['password'] == password:
                # Generate JWT token
                token = generate_token(user['id'], user['name'])
                return jsonify({'message': 'Login successful', 'token': token}), 200
            else:
                return jsonify({'error': 'Invalid user password'}), 401
        else:
            return jsonify({'error': 'Invalid username and password'}), 401
    except Exception as e:
        print(e)
        return jsonify({'error': 'Login failed'}), 500
    finally:
        if connection:
            connection.close()

# Profile endpoint
@app.route('/api2/user/profile', methods=['GET', 'POST'])
def api2_profile():
    # Get token from Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token missing'}), 401

    try:
        # Decode and verify the token
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        user_id = payload['user_id']
        username = payload['name']

        # Fetch user details from the database
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute('SELECT id, name, email, role FROM rest_user WHERE id = %s AND name = %s', (user_id, username))
        user = cursor.fetchone()

        if user:
            if request.method == 'GET':
                return jsonify({'user': user}), 200
            elif request.method == 'POST':
                # Update user details (excluding password, id, and role)
                data = request.get_json()
                new_email = data.get('email', user['email'])
                new_name = data.get('name', user['name'])

                # Check if the updated email and name already exist in the database
                cursor.execute('SELECT * FROM rest_user WHERE (email = %s OR name = %s) AND id != %s',
                               (new_email, new_name, user_id))
                existing_user = cursor.fetchone()

                if existing_user:
                    return jsonify({'error': 'User already exists'}), 400

                cursor.execute('UPDATE rest_user SET email = %s, name = %s WHERE id = %s',
                               (new_email, new_name, user_id))
                connection.commit()

                return jsonify({'message': 'User profile updated successfully'}), 200
        else:
            return jsonify({'error': 'User not found'}), 404
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        print(e)
        return jsonify({'error': 'Profile retrieval or update failed'}), 500
    finally:
        if connection:
            connection.close()

# User details endpoint
@app.route('/api2/user/<int:user_id>', methods=['GET'])
def api2_user_details(user_id):
    # Get token from Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token missing'}), 401

    try:
        # Decode and verify the token
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        requester_id = payload['user_id']

        # Allow access for GET if the requester is authenticated
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        if request.method == 'GET':
            # Fetch user details based on the provided user ID
            cursor.execute('SELECT * FROM rest_user WHERE id = %s', (user_id,))
            user = cursor.fetchone()

            if user:
                return jsonify({'user': user}), 200
            else:
                return jsonify({'error': 'User not found'}), 404
        else:
            return jsonify({'error': 'Invalid method'}), 405

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        print(e)
        return jsonify({'error': 'User details retrieval failed'}), 500
    finally:
        if connection:
            connection.close()

# Update password endpoint
@app.route('/api2/user/profile/update-password', methods=['POST', 'PUT'])
def api2_update_password():
    # Get token from Authorization header
    token = request.headers.get('Authorization')
    username_param = request.json.get('username')
    new_password = request.json.get('new-password')

    try:
        connection = create_connection()
        cursor = connection.cursor()

        if request.method == 'POST':
            # Decode and verify the token if provided
            if token:
                payload = jwt.decode(token, secret_key, algorithms=['HS256'])
                user_id = payload['user_id']
                username = payload['name']

                # Check if the username in the token matches the username parameter
                if username_param != username:
                    return jsonify({'error': 'Unauthorized operation'}), 401
            else:
                # Check if the username exists
                cursor.execute('SELECT * FROM rest_user WHERE name = %s', (username_param,))
                user = cursor.fetchone()

                if not user:
                    return jsonify({'error': 'User not found'}), 404

                user_id = user[0]
                username = user[1]

            # Allow updating password for the current user using POST
            cursor.execute('UPDATE rest_user SET password = %s WHERE id = %s', (new_password, user_id))
            connection.commit()
            return jsonify({'message': 'Password updated successfully'}), 200

        elif request.method == 'PUT':
            # Allow changing any user's password using PUT
            cursor.execute('UPDATE rest_user SET password = %s WHERE name = %s', (new_password, username_param))
            connection.commit()
            return jsonify({'message': 'Password updated successfully'}), 200

        else:
            return jsonify({'error': 'Invalid method'}), 405

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        print(e)
        return jsonify({'error': 'Password update failed'}), 500
    finally:
        if connection:
            connection.close()

# User chat endpoint
@app.route('/api2/user/chat', methods=['GET'])
def api2_user_chat():
    # Get token from Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token missing'}), 401

    try:
        # Decode and verify the token
        jwt.decode(token, secret_key, algorithms=['HS256'])
        
        # Display a message indicating that this feature is currently being updated
        return jsonify({'message': 'This feature is currently being updated. Stay tuned!'}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        print(e)
        return jsonify({'error': 'Chat feature retrieval failed'}), 500

# Admin panel endpoint
@app.route('/api2/user/admin', methods=['GET'])
def api2_user_admin():
    # Get token from Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token missing'}), 401

    # Check if the user is an admin
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        user_id = payload['user_id']
        name = payload['name']

        connection = create_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute('SELECT role FROM rest_user WHERE id = %s AND name = %s', (user_id, name))
        user = cursor.fetchone()

        if user and user['role'] == 'admin':
            # Get URL or file parameter from the query string
            url_param = request.args.get('url')
            file_param = request.args.get('file')

            if url_param:
                # Load external URL
                response = requests.get(url_param)
                return response.text, response.status_code
            elif file_param:
                # Load file content from the server
                file_path = os.path.abspath(file_param)
                with open(file_path, 'r') as file:
                    content = file.read()
                return content, 200
            else:
                return jsonify({'message': 'Welcome to the admin panel! Feel free to explore and try to fuzz for the next challenge!'}), 200

        else:
            return jsonify({'error': 'Admin access denied'}), 403

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        print(e)
        return jsonify({'error': 'Admin check failed'}), 500
    finally:
        if connection:
            connection.close()

# Admin delete user account endpoint
@app.route('/api2/user/admin/<string:username>', methods=['DELETE'])
def api2_admin_delete_user(username):
    # Get token from Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token missing'}), 401

    try:
        # Decode and verify the token
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        requester_id = payload['user_id']

        # Allow DELETE if the requester is authenticated
        connection = create_connection()
        cursor = connection.cursor()

        # Delete the user account based on the provided username
        cursor.execute('DELETE FROM rest_user WHERE name = %s', (username,))
        connection.commit()

        if cursor.rowcount > 0:
            return jsonify({'message': 'User account deleted successfully'}), 200
        else:
            return jsonify({'error': 'User not found or deletion failed'}), 404
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        print(e)
        return jsonify({'error': 'User account deletion failed'}), 500
    finally:
        if connection:
            connection.close()

# Admin view all users endpoint
@app.route('/api2/user/admin/all-user', methods=['GET'])
def api2_admin_view_all_users():
    # Get token from Authorization header
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token missing'}), 401

    try:
        # Decode and verify the token
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        requester_id = payload['user_id']

        # Allow GET if the requester is an admin
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        # Check if the requester is an admin
        cursor.execute('SELECT role FROM rest_user WHERE id = %s', (requester_id,))
        user = cursor.fetchone()

        if user and user['role'] == 'admin':
            # Fetch all user details
            cursor.execute('SELECT id, name, email, role FROM rest_user')
            users = cursor.fetchall()
            return jsonify({'users': users}), 200
        else:
            return jsonify({'error': 'Admin access denied'}), 403
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        print(e)
        return jsonify({'error': 'Admin view all users failed'}), 500
    finally:
        if connection:
            connection.close()

# User class definition
class User:
    def __init__(self, username, email, admin, chat):
        self.username = username
        self.email = email
        self.admin = admin
        self.chat = chat

# Endpoint to register a new user
@app.route('/api1/user/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    try:
        connection = create_connection()
        cursor = connection.cursor()

        # Insert user data into the old_db table
        cursor.execute('INSERT INTO old_db (username, password, email) VALUES (%s, %s, %s)',
                       (username, password, email))
        connection.commit()

        return jsonify({'message': 'Registration successful'}), 201
    except Exception as e:
        print(e)
        return jsonify({'error': 'Registration failed'}), 500
    finally:
        if connection:
            connection.close()

# Endpoint to login
@app.route('/api1/user/login', methods=['POST', 'GET'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    try:
        connection = create_connection()
        cursor = connection.cursor(dictionary=True)

        # Insecure: Use concatenated query to introduce SQL injection
        cursor.execute(f'SELECT * FROM old_db WHERE username = "{username}" AND password = "{password}"')
        user = cursor.fetchone()

        if user:
            # Generate a random 'session'
            session = secrets.token_urlsafe(32)

            # Update the 'session' column in the database
            cursor.execute('UPDATE old_db SET session = %s WHERE username = %s', (session, username))
            connection.commit()

            # Set the 'session' as a cookie
            response = make_response(jsonify({'message': 'Login successful'}), 200)
            response.set_cookie('session', session)
            return response
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        print(e)
        return jsonify({'error': 'Login failed'}), 500
    finally:
        if connection:
            connection.close()

# Updated secure function: Execute shell commands using user input
def execute_command(command):
    try:
        # Split the command using shlex to handle arguments safely
        command_args = shlex.split(command)
        
        # Execute the command with subprocess
        result = subprocess.run(command_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        return result.stdout.decode()
    except Exception as e:
        # Handle any exceptions that may occur during command execution
        return f"Error: {str(e)}"


# Endpoint to retrieve user profile and update user profile
@app.route('/api1/user/profile', methods=['GET', 'POST'])
def profile():
    # Get the 'session' from the cookie
    session = request.cookies.get('session')

    if session:
        if request.method == 'GET':
            # Fetch user data from the database using 'session'
            connection = create_connection()
            cursor = connection.cursor(dictionary=True)
            cursor.execute('SELECT * FROM old_db WHERE session = %s', (session,))
            user = cursor.fetchone()

            if user:
                # Convert the User object to a dictionary for JSON serialization
                user_dict = {
                    'username': user['username'],
                    'email': user['email'],
                    'admin': user['admin'],
                    'chat': user['chat']
                }

                return jsonify({'user': user_dict}), 200
            else:
                return jsonify({'error': 'User data not found'}), 401

        elif request.method == 'POST':
            # Get the updated user data from the request
            updated_data = request.get_json()

            # Fetch user data from the database using 'session'
            connection = create_connection()
            cursor = connection.cursor(dictionary=True)
            cursor.execute('SELECT * FROM old_db WHERE session = %s', (session,))
            user = cursor.fetchone()

            if user:
                # Update user profile with the new data
                update_columns = []
                update_values = []

                # Dynamically construct the SET clause based on the provided data
                for column, value in updated_data.items():
                    update_columns.append(f'{column} = %s')
                    update_values.append(value)

                # Construct and execute the UPDATE query
                update_query = f'UPDATE old_db SET {", ".join(update_columns)} WHERE session = %s'
                update_values.append(session)  # Add session to the WHERE clause
                cursor.execute(update_query, tuple(update_values))
                connection.commit()

                # Save the chat message to a file (insecure)
                if 'chat' in updated_data:
                    chat_message = updated_data['chat']
                    os.system(f'echo {chat_message} > /dev/null 2>/dev/null')  # Redirect errors to /dev/null

                # Return a success message
                return jsonify({'message': 'User profile updated successfully'}), 200
            else:
                return jsonify({'error': 'User data not found'}), 401

    else:
        return jsonify({'error': 'User data not found'}), 401

# Endpoint to retrieve all user chats
@app.route('/api1/user/chat', methods=['GET'])
def all_chats():
    # Get all chats from the database
    connection = create_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute('SELECT username, chat FROM old_db')
    all_chats = cursor.fetchall()

    # Convert the list of chats to a dictionary for JSON serialization
    chats_list = [{'username': chat['username'], 'chat': chat['chat']} for chat in all_chats]

    return jsonify({'chats': chats_list}), 200


# Run the application
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
