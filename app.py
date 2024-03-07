from flask import Flask, flash, request, jsonify, session, render_template, redirect, url_for
import mysql.connector
import bcrypt
import secrets
from flask_login import LoginManager, login_user, UserMixin, current_user
from urllib.parse import quote, unquote, urlencode

""" from flask import Flask, flash, request, jsonify, session, render_template, redirect, url_for
import mysql.connector
import bcrypt
import secrets
from flask_login import LoginManager, login_user, UserMixin, current_user
from oauthlib.oauth2 import WebApplicationClient
#from oauthlib.oauth2 import OAuth2Session
from requests_oauthlib import OAuth2Session
from urllib.parse import quote, unquote, urlencode
from cryptography import x509 """


# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(24)

# Create MySQL Database Connection
connection = mysql.connector.connect(
    host='162.241.244.25',
    user='uahqojmy_TaSharma',
    password='Ects0131!!!',
    database='uahqojmy_student_TaSharma'
)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

microsoft = None

""" def create_microsoft_session(client_id, redirect_uri, scope):
    global microsoft
    microsoft = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)    
    return microsoft """

@login_manager.user_loader
def load_user(user_id):
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    cursor.execute('SELECT * FROM User WHERE Id = %s', (user_id,))
    user = cursor.fetchone()
    if user:
        return User(user['Id'], user['display_name'], user['email'])
    return None

#client = WebApplicationClient('baf988fb-4544-4dcf-a47d-4e21a533c2db')

""" # Define Microsoft OAuth2 variables
client_id = 'baf988fb-4544-4dcf-a47d-4e21a533c2db'
client_secret = 'gh88Q~Z5S9YPafojtomr6qOo-osGsufKmil5ia90'
authorize_url = 'https://login.microsoftonline.com/e34fd78b-f48d-4235-9787-fef76723be14/oauth2/v2.0/authorize'
access_token_url = 'https://login.microsoftonline.com/e34fd78b-f48d-4235-9787-fef76723be14/oauth2/v2.0/token'
userinfo_endpoint = 'https://graph.microsoft.com/v1.0/me'
redirect_uri = 'http://localhost:5000/callback' """


""" microsoft = create_microsoft_session(client_id, redirect_uri, ['openid', 'email', 'profile'])
 """
@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('teacher_dashboard.html')


#http://localhost:5000/callback'
@app.route('/callback', methods=['GET','POST'])
def microsoft_callback():
    print("in callback")
    auth_code = request.args.get('code')
    if auth_code:
        # Exchange authorization code for tokens
        """ token = microsoft.fetch_token(
            access_token_url,
            authorization_response=request.url,
            client_secret=client_secret
        ) """

        # Redirect to the authorized route for further processing
        return redirect(url_for('authorized'))
    else:
        # Handle error case when no auth code is received
        return 'Authentication failed'



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

""" @app.route('/login/authorized')
def authorized():
    # Check the OAuth state
    if request.args.get('state') != session.get('oauth_state'):
        return 'Invalid OAuth state'

    token = microsoft.fetch_token(
        access_token_url,
        authorization_response=request.url,
        client_secret=client_secret
    )

    # Fetch user details from Microsoft Graph API
    me = microsoft.get(userinfo_endpoint).json()
    user_email = me['userPrincipalName']
    user_display_name = me['displayName']
    given_name = me['givenName']
    surname = me['surname']

    # Check if the user exists in the User table
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    cursor.execute('SELECT * FROM User WHERE email = %s', (user_email,))
    existing_user = cursor.fetchone()

    if not existing_user:
        # User doesn't exist, create a new user in the User table
        cursor.execute('''
            INSERT INTO User (email, display_name, givenName, surname)
            VALUES (%s, %s, %s, %s)
        ''', (user_email, user_display_name, given_name, surname))
        connection.commit()

        # Fetch the newly created user from the User table
        cursor.execute('SELECT * FROM User WHERE email = %s', (user_email,))
        user = cursor.fetchone()

        # Log in the user using Flask-Login
        login_user(User(user['Id'], user['display_name'], user['email']))

        # Insert a new entry into the User_Role table
        insert_user_role_query = '''
            INSERT INTO User_Role (User_Id, Role_Id) VALUES (%s, %s)
        '''
        cursor.execute(insert_user_role_query, (user['Id'], 1))  # Assuming Role_Id = 1 is the default role for teacher
        connection.commit()

        # Redirect the user to their teacher dashboard
        return redirect(url_for('teacher_dashboard'))

    # Fetch the existing user from the User table
    user = existing_user

    # Log in the user using Flask-Login
    login_user(User(user['Id'], user['display_name'], user['email']))

    # Fetch the role of the user from the User_Role table
    cursor.execute('''
        SELECT r.role_name 
        FROM Role r 
        JOIN User_Role ur ON r.id = ur.Role_Id 
        WHERE ur.User_Id = %s
    ''', (user['Id'],))
    role = cursor.fetchone()
    return redirect(url_for('teacher_dashboard')) """




class User(UserMixin):
    def __init__(self, id, display_name, email):
        self.id = id
        self.display_name = display_name
        self.email = email


# secret_key = secrets.token_urlsafe(24)

# app = Flask(__name__)
# app.secret_key = secret_key

# # MySQL Database Connection
# connection = mysql.connector.connect(
#     host='162.241.244.25',
#     user='uahqojmy_TaSharma',
#     password='Ects0131!!!',
#     database='uahqojmy_student_TaSharma'
# )

@app.route('/create_request')
def create_request():
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    cursor.execute('SELECT Id, display_name FROM Lab')
    labs = cursor.fetchall()

    cursor.execute('SELECT Id, Display FROM Request_Type')
    request_types = cursor.fetchall()

    return render_template('create_request.html', labs=labs, request_types=request_types)


@app.route('/submit_request', methods=['POST'])
def submit_request():
    user_id = session.get('user_id')
    lab_id = request.form['lab_id']
    requested_date = request.form['requested_date']
    description = request.form['description']
    unit_price = request.form['unit_price']
    quantity = request.form['quantity']
    oac_recommended_date = request.form['oac_recommended_date']
    request_type_id = request.form['request_type_id']  
    additional_notes = request.form['additional_notes']

     # Check if the "Save as Draft" button is clicked
    if 'save_as_draft' in request.form:
        state_id = 1  # Set State_Id to 1 (draft)
    else:
        state_id = 3  # Set State_Id to 3 (submitted)

    # Establish a cursor to execute SQL queries
    connection.reconnect()
    cursor = connection.cursor()

    insert_query = '''
    INSERT INTO Request (User_Id, Lab_Id, Requested_Date, Description, Unit_Price, Quantity,
                        OAC_Recommended_Date, Request_Type_Id, Additional_Notes, State_Id)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    '''
    # Execute the query with the provided form data and User_Id
    cursor.execute(insert_query, (
        user_id, lab_id, requested_date, description, unit_price, quantity,
        oac_recommended_date, request_type_id, additional_notes, state_id
    ))

    # Commit the changes to the database
    connection.commit()

    role_query = '''
    SELECT Role_Id FROM Request_Type_Require_Roles WHERE Request_Type_Id = %s
    '''
    cursor.execute(role_query, (request_type_id,))
    associated_roles = cursor.fetchall()

    # Notify/send the request to identified admins/roles (Example: Flashing a message)
    if associated_roles:
        for role in associated_roles:
            # For example, you can display roles using flash messages
            flash(f"Request sent to role with ID: {role[0]}")  # Access tuple elements by index

            # Insert a message into the Message table for admins
            message_query = '''
            INSERT INTO Message (Sender_Id, Recipient_Id, Content, Is_Read, Date)
            VALUES (%s, %s, %s, %s, NOW())
            '''
            admin_id = fetch_admin_id_by_role(role[0])  # Assuming you have a function to fetch admin ID by role
            cursor.execute(message_query, (user_id, admin_id, f"A new request requires your attention. Request ID: {cursor.lastrowid}", 0))
            connection.commit()
    cursor.close()

    # For now, simply return a success message after receiving the form data
    return "Request submitted successfully!"


def fetch_admin_id_by_role(role_display):
    connection.reconnect()
    cursor = connection.cursor()
    query = 'SELECT User_Id FROM User_Role WHERE Role_Id = (SELECT Id FROM Role WHERE Display = %s)'
    cursor.execute(query, (role_display,))
    admin_id = cursor.fetchone()
    if admin_id:
        return admin_id[0]
    else:
        return None



@app.route('/')
def home():
    return render_template('login.html')

# Function to fetch a teacher's current and past requaests
def get_teacher_requests(user_id):
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    #query = "select * from users where userid = " + somevar + " " #this is bad because
    #what people do is fill out the form with a field like "; drop database users;" 
    # Fetch requests based on user_id (assuming user_id corresponds to the teacher)
    query = '''
    SELECT r.*, rt.Display AS Request_Type, s.Display AS State
    FROM Request r
    JOIN Request_Type rt ON r.Request_Type_Id = rt.Id
    JOIN State s ON r.State_Id = s.Id
    WHERE r.User_Id = %s
    ORDER BY r.Requested_Date DESC
    '''
    cursor.execute(query, (user_id,))
    requests = cursor.fetchall()

    return requests


def fetch_response_comments(request_id):
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    query = '''
        SELECT Notes
        FROM Response
        WHERE Request_Id = %s
    '''
    cursor.execute(query, (request_id,))
    comments = cursor.fetchall()
    return [comment['Notes'] for comment in comments]


@app.route('/teacher_dashboard.html')
def teacher_dashboard():
    # user_id = session.get('user_id')
    user_id = current_user.id
    email = current_user.email
    display_name = current_user.display_name

    # Check if user_id exists in the session
    if user_id is None:
        return render_template('login.html')  # Redirect to the login page

    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    cursor.execute('SELECT * FROM User WHERE id = %s', (user_id,))
    user = cursor.fetchone()

    if user:
        # Fetching display_name from User table
        display_name = user['display_name']

        # Fetching role Display from Role table using User_Role table
        cursor.execute('''
            SELECT Role.Long_Description, Role.Display
            FROM Role
            JOIN User_Role ON Role.Id = User_Role.Role_Id
            WHERE User_Role.User_Id = %s
        ''', (user_id,))
        role_data = cursor.fetchone()
        role_long_description = role_data['Long_Description']
        role_display = role_data['Display'] if 'Display' in role_data else None

        # Fetching the user's requests directly from the Request table using User_Id
        query = '''
            SELECT r.*, rt.Display AS Request_Type, s.Display AS State
            FROM Request r
            JOIN Request_Type rt ON r.Request_Type_Id = rt.Id
            JOIN State s ON r.State_Id = s.Id
            WHERE r.User_Id = %s
            ORDER BY r.Requested_Date DESC
        '''
        cursor.execute(query, (user_id,))
        user_requests = cursor.fetchall()

        # Update the State field to include the display name
        for request in user_requests:
            state_id = request['State_Id']
            state_display = fetch_state_display(state_id)
            request['State_Display'] = state_display

            # Fetch comments from the Response table
            request['Comments'] = fetch_response_comments(request['Id'])

        # Filter requests to display only the ones matching the current user's ID
        user_requests = [req for req in user_requests if req['User_Id'] == user_id]

        print("User Requests:", user_requests)

        user_details = {
            'email': user['email'],
            'name': display_name,  # Using display_name from User table as 'name'
            'role': role_long_description,   # Fetching role Long_Description from Role table
            'role2': role_display,
            'user_requests': user_requests,  # Adding user's requests to the dictionary
            'user_id': user_id  # Pass user_id to the template
        }

        # Fetch messages for the user
        messages_query = '''
            SELECT m.*, u.display_name AS sender_name
            FROM Message m
            JOIN User u ON m.Sender_Id = u.Id
            WHERE m.Recipient_Id = %s AND m.Is_Read = 0
        '''
        cursor.execute(messages_query, (user_id,))
        unread_messages = cursor.fetchall()

        # Update messages as read
        update_messages_query = '''
            UPDATE Message SET Is_Read = 1 WHERE Recipient_Id = %s
        '''
        cursor.execute(update_messages_query, (user_id,))
        connection.commit()

        # Remove unread messages
        unread_messages = []  # Empty list to remove unread messages

        return render_template('teacher_dashboard.html', user=user_details, unread_messages=unread_messages)
    else:
        return render_template('login.html')
    

def fetch_state_display(state_id):
    connection.reconnect()
    cursor = connection.cursor()
    query = 'SELECT Display FROM State WHERE Id = %s'
    cursor.execute(query, (state_id,))
    state_display = cursor.fetchone()
    if state_display:
        return state_display[0]
    else:
        return None



def fetch_user_role_description(user_id):
    # Assuming you have a function to fetch the user's role description from the database
    # Establish a database connection and execute a query to fetch the user's role description
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    query = '''
        SELECT Role.Long_Description
        FROM Role
        JOIN User_Role ON Role.Id = User_Role.Role_Id
        WHERE User_Role.User_Id = %s
    '''
    cursor.execute(query, (user_id,))
    role_description = cursor.fetchone()
    if role_description:
        return role_description['Long_Description']  # Assuming the role description is in the 'Display' column
    else:
        return None  # Return None or a default value if the role description isn't found


@app.route('/admin_dashboard.html')
def admin_dashboard():
    # user_id = session.get('user_id')
    user_id = current_user.id
    email = current_user.email
    display_name = current_user.display_name

    if user_id is None:
        return render_template('login.html')  # Redirect to login page

    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    cursor.execute('SELECT * FROM User WHERE Id = %s', (user_id,))
    user = cursor.fetchone()

    if user:
        # Fetching display_name from User table
        display_name = user['display_name']

        # Fetching role using the updated function
        admin_role = fetch_user_role(user_id)
        if admin_role != 'admin':
            return "You don't have permission to access this page."

        # Fetching the list of requests for the admin to process
        query = '''
            SELECT r.*, u.display_name AS name, rt.Display AS Request_Type, s.Display AS State
            FROM Request r
            JOIN User u ON r.User_Id = u.Id
            JOIN Request_Type rt ON r.Request_Type_Id = rt.Id
            JOIN State s ON r.State_Id = s.Id
            WHERE r.State_Id = 3 
            ORDER BY r.Requested_Date DESC
        '''
        cursor.execute(query)
        requests = cursor.fetchall()

        user_details = {
            'email': user['email'],
            'name': display_name,
            'role': 'Admin'  # Set role explicitly for admin
        }
        return render_template('admin_dashboard.html', user=user_details, requests=requests)
    else:
        return render_template('login.html')  # Redirect to login if user details not found



    


@app.route('/process_request/<int:request_id>', methods=['POST'])
def process_request(request_id):
    user_id = session.get('user_id')
    if user_id is None:
        return render_template('login.html')

    # Check if the user has the admin role
    admin_role = fetch_user_role(user_id)
    if admin_role != 'admin':
        return "You don't have permission to process requests."

    # Get the admin's decision and comments
    action = request.form.get('action')
    comments = request.form.get('comments')

    connection.reconnect()
    cursor = connection.cursor()

    # Determine the state_id and response_type_id based on the admin's action
    if action == 'approve':
        state_id = 4  # Approve with comments
        response_type_id = 4  
    elif action == 'deny':
        state_id = 6  # Deny with reason
        response_type_id = 5  

        # Set State_Id to 6 when admin denies the request
        connection.reconnect()
        cursor = connection.cursor()
        update_query = '''
            UPDATE Request
            SET State_Id = %s
            WHERE Id = %s
        '''
        cursor.execute(update_query, (state_id, request_id))
        connection.commit()
    elif action == 'return':
        state_id = 7  # Return to teacher and ask for more details
        response_type_id = 6
    try:
        # Update the request state based on the admin's action
        update_query = '''
            UPDATE Request
            SET State_Id = %s
            WHERE Id = %s
        '''
        cursor.execute(update_query, (state_id, request_id))
        connection.commit()

        # Save the admin's comments in the Response table
        response_query = '''
            INSERT INTO Response (User_Id, Request_Id, Response_Type_Id, Date, Notes)
            VALUES (%s, %s, %s, NOW(), %s)
        '''
        cursor.execute(response_query, (user_id, request_id, response_type_id, comments))
        connection.commit()

    finally:
        cursor.close()

    return redirect(url_for('admin_dashboard'))



def fetch_user_role(user_id):
    connection.reconnect()
    cursor = connection.cursor()
    query = 'SELECT Role.Display FROM Role JOIN User_Role ON Role.Id = User_Role.Role_Id WHERE User_Role.User_Id = %s'
    cursor.execute(query, (user_id,))
    role = cursor.fetchone()
    if role:
        return role[0]
    else:
        return None

# @app.route('/logout')
# def logout():
#     session.clear()  # Clear the session data
#     return redirect(url_for('home'))  # Redirect to the home page or login page

@app.route('/completed_requests_table')
def completed_requests_table():
    # user_id = session.get('user_id')
    user_id = current_user.id
    email = current_user.email
    display_name = current_user.display_name

    # Check if the user has the admin role
    admin_role = fetch_user_role(user_id)

    if admin_role != 'admin':
        return "You don't have permission to access this page."

    connection.reconnect()
    cursor = connection.cursor(dictionary=True)

    # Fetch user details
    cursor.execute('SELECT * FROM User WHERE Id = %s', (user_id,))
    user = cursor.fetchone()

    if user:
        # Fetching display_name from User table
        display_name = user['display_name']

        # Fetching the list of completed requests (State_Id = 4) with Unit_Price and Quantity
        query = '''
            SELECT r.*, u.display_name AS name, rt.Display AS Request_Type, s.Display AS State,
                   r.Unit_Price, r.Quantity  -- Include Unit_Price and Quantity
            FROM Request r
            JOIN User u ON r.User_Id = u.Id
            JOIN Request_Type rt ON r.Request_Type_Id = rt.Id
            JOIN State s ON r.State_Id = s.Id
            WHERE r.State_Id = 4
            ORDER BY r.Requested_Date DESC
        '''
        cursor.execute(query)
        completed_requests = cursor.fetchall()

        user_details = {
            'email': user['email'],
            'name': display_name,
            'role': 'Admin'
        }

        return render_template('completed_requests_table.html', user=user_details, completed_requests=completed_requests)

    else:
        return render_template('login.html')  # Redirect to login if user details not found





# @app.route('/login.html', methods=['POST'])
# def login():
#     username = request.form.get('username')
#     password = request.form.get('password')
#     connection.reconnect()
#     cursor = connection.cursor(dictionary=True)
#     cursor.execute('SELECT * FROM User WHERE email = %s', (username,))
#     user = cursor.fetchone()

#     if user and user['password'] == password:
#         # Fetch the user's role description from User_Role and Role tables
#         cursor.execute('SELECT Role_Id FROM User_Role WHERE User_Id = %s', (user['Id'],))
#         role_id = cursor.fetchone()['Role_Id']

#         cursor.execute('SELECT Display FROM Role WHERE Id = %s', (role_id,))
#         role_description = cursor.fetchone()['Display']

#         # Set the 'user_id' in the session
#         session['user_id'] = user['Id']

#         # Redirect the user to their respective dashboard based on their role description
#         if role_description == 'teacher':
#             return redirect(url_for('teacher_dashboard'))
#         elif role_description == 'admin':
#             return redirect(url_for('admin_dashboard'))

#     # If authentication fails or user doesn't have appropriate role, redirect to login page
#     return render_template('login.html')


@app.route('/edit_request/<int:request_id>', methods=['GET', 'POST'])
def edit_request(request_id):
    user_id = session.get('user_id')
    if user_id is None:
        return render_template('login.html')

    connection.reconnect()
    cursor = connection.cursor(dictionary=True)

    if request.method == 'GET':
        # Fetch the user request from the database
        query = '''
            SELECT * FROM Request
            WHERE Id = %s AND User_Id = %s
        '''
        cursor.execute(query, (request_id, user_id))
        user_request = cursor.fetchone()

        if user_request:
            # Check if the request is completed or denied
            if user_request['State_Id'] in [4, 6]:
                return "Request is completed or denied. Cannot edit."

            cursor.execute('SELECT Id, display_name FROM Lab')
            labs = cursor.fetchall()

            cursor.execute('SELECT Id, Display FROM Request_Type')
            request_types = cursor.fetchall()

            # Render a form to edit the request with prefilled details
            return render_template('edit_request.html', request=user_request, labs=labs, request_types=request_types)
        else:
            return "Request not found or you don't have permission to edit it."
    elif request.method == 'POST':
        # Update the request based on the form data
        lab_id = request.form.get('lab_id')
        requested_date = request.form.get('requested_date')
        description = request.form.get('description')
        unit_price = request.form.get('unit_price')
        quantity = request.form.get('quantity')
        oac_recommended_date = request.form.get('oac_recommended_date')
        request_type_id = request.form.get('request_type_id')
        additional_notes = request.form.get('additional_notes')

        # Fetch the user request from the database
        query = '''
            SELECT * FROM Request
            WHERE Id = %s AND User_Id = %s
        '''
        cursor.execute(query, (request_id, user_id))
        user_request = cursor.fetchone()

        if user_request:
            # Check if the request is completed or denied
            if user_request['State_Id'] in [4, 6]:
                return "Request is completed or denied. Cannot edit."

            # Check if the state is 7 (return for more detail)
            if user_request['State_Id'] == 7:
                # Update the State_Id to 3
                update_state_query = '''
                    UPDATE Request
                    SET State_Id = 3
                    WHERE Id = %s AND User_Id = %s
                '''
                cursor.execute(update_state_query, (request_id, user_id))
                connection.commit()

            # Update the request in the database
            update_query = '''
                UPDATE Request
                SET Lab_Id = %s, Requested_Date = %s, Description = %s, Unit_Price = %s,
                    Quantity = %s, OAC_Recommended_Date = %s, Request_Type_Id = %s,
                    Additional_Notes = %s
                WHERE Id = %s AND User_Id = %s
            '''
            cursor.execute(update_query, (
                lab_id, requested_date, description, unit_price, quantity, oac_recommended_date,
                request_type_id, additional_notes, request_id, user_id
            ))
            connection.commit()

            return redirect(url_for('teacher_dashboard'))
        else:
            return "Request not found or you don't have permission to edit it."



@app.route('/remove_request/<int:request_id>', methods=['POST'])
def remove_request(request_id):
    user_id = session.get('user_id')
    if user_id is None:
        return render_template('login.html')

    # Check if the request exists and belongs to the user
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    query = '''
        SELECT * FROM Request
        WHERE Id = %s AND User_Id = %s
    '''
    cursor.execute(query, (request_id, user_id))
    user_request = cursor.fetchone()

    if user_request:
        # Delete the request from the database
        delete_query = '''
            DELETE FROM Request
            WHERE Id = %s AND User_Id = %s
        '''
        cursor.execute(delete_query, (request_id, user_id))
        connection.commit()
        return redirect(url_for('teacher_dashboard'))
    else:
        return "Request not found or you don't have permission to remove it."



if __name__ == '__main__':
    app.run(ssl_context='adhoc', debug=True)
