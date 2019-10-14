from flask import Flask, request, url_for, render_template, redirect, session
from random import random
import subprocess
import os

# setting up the app
SECRET_KEY = 'supersecretkey'

app = Flask(__name__)
app.config.from_object(__name__)

# our users "database"
users = {
    'roman': {
        'uid': 100,
        'pword': 'letmein',  # TODO: look ma, default credentials with clear text password
        'two_fa': '9876543210'
    }
}


# Managing the status massage functions
def get_status():
    status = {'status_message': '', 'element_id': ''}
    if 'status' in session:
        status = session['status']
        session.pop('status')

    return status


def set_status(status_message, element_id):
    session['status'] = {'status_message': status_message, 'element_id': element_id}


def is_status():
    if 'status' in session:
        return True
    else:
        return False


def login_user(uname, pword, two_fa):
    # User login checks

    # Check if user exists, and if so get the user
    user = users.get(uname)
    if user is None:
        set_status('Login failed, username or password incorrect', 'result')
        return False

    # Check if password is valid
    our_password = user.get('pword')
    in_password = pword
    if our_password != in_password:
        set_status('Login failed, username or password incorrect', 'result')
        return False

    # Check if our 2fa simulation is valid or not
    our_2fa = user.get('two_fa')
    in_2fa = two_fa
    if our_2fa != in_2fa:
        set_status('Two-factor authentication failure', 'result')
        return False

    return True


# Our route begins
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form.get('uname')
        pword = request.form.get('pword')  # TODO: look ma, cleartext password
        two_fa = request.form.get('2fa')
        uid = len(users) + 100
        csrf_token = request.form.get('csrf_token')

        # CSRF Check
#        our_token = session.get('csrf_token')
#        if csrf_token != our_token:
#            return render_template('404.html')
        session.pop('csrf_token', None)

        # Registration Checks
        # TODO: Validate input
        # TODO: Check for password complexity
        # does user already exist
        if uname in users:
            set_status('Registration failure - user exists', 'success')

        # If our status is set registration failed
        if is_status():
            session['csrf_token'] = str(random())  # Implement basic CSRF protection
            return render_template('register.jinja2', status=get_status(), csrf_token=session.get('csrf_token'))

        # Otherwise register user
        users[uname] = {'uid': uid, 'pword': pword, 'two_fa': two_fa}
        set_status('Registration success - now please login', 'success')
        return redirect(url_for('login'))
    else:
        session['csrf_token'] = str(random())  # Implement basic CSRF protection
        return render_template('register.jinja2', status=get_status(), csrf_token=session.get('csrf_token'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form.get('uname')
        pword = request.form.get('pword')  # TODO: look ma, cleartext password
        two_fa = request.form.get('2fa')
        csrf_token = request.form.get('csrf_token')

        # CSRF Check
#        our_token = session.get('csrf_token')
#        if csrf_token != our_token:
#            return render_template('404.html')
        session.pop('csrf_token', None)

        # TODO: Validate input

        if not login_user(uname, pword, two_fa):
            session['csrf_token'] = str(random())  # Implement basic CSRF protection
            return render_template('login.jinja2', status=get_status(), csrf_token=session.get('csrf_token'))

        # Yeepee - looks like we have a valid user lets log them in
        user = users.get(uname)
        session['uid'] = user.get('uid')
        set_status('Login success', 'result')
        return redirect(url_for('spell_check'))

    else:
        session['csrf_token'] = str(random())  # Implement basic CSRF protection
        return render_template('login.jinja2', status=get_status(), csrf_token=session.get('csrf_token'))


@app.route('/spell_check', methods=['GET', 'POST'])
def spell_check():
    if request.method == 'POST':

        # Access control check - make sure the user can do this
        user = session.get('uid')
        if user is None:
            set_status('Authentication required', 'success')
            return render_template('spell_check.jinja2', status=get_status(), uid=session.get('uid'))

        inputtext = request.form.get('inputtext')
        csrf_token = request.form.get('csrf_token')

        # CSRF Check
        our_token = session.get('csrf_token')
        if csrf_token != our_token:
            return render_template('404.html')
        session.pop('csrf_token', None)

        # TODO: validate input
        if inputtext is None or len(inputtext) <= 0:
            set_status('Please enter some text', 'status')
            uid = session.get('uid')
            session['csrf_token'] = str(random())  # Implement basic CSRF protection
            return render_template('spell_check.jinja2', status=get_status(), uid=session.get('uid'),
                                   csrf_token=session.get('csrf_token'))



        # Do the spell check
        file_to_check = open('file_to_check.txt', "w+")
        file_to_check.write(inputtext)
        file_to_check.close()

        spell_proc = subprocess.run(
            ['./a.out', './file_to_check.txt', './wordlist.txt'],
            stdout=subprocess.PIPE,
        )
        os.remove('./file_to_check.txt')

        if spell_proc.returncode != 0:
            return render_template('404.html')

        text = inputtext
        output = spell_proc.stdout.decode('utf-8')
        misspelled = output.replace("\n", ", ").strip().strip(',')

        return render_template('spell_check_result.jinja2', status=get_status(), uid=session.get('uid'), text=text,
                               misspelled=misspelled)
    else:
        uid = session.get('uid')
        session['csrf_token'] = str(random())  # Implement basic CSRF protection
        return render_template('spell_check.jinja2', status=get_status(), uid=session.get('uid'),
                               csrf_token=session.get('csrf_token'))


if __name__ == '__main__':
    app.run(debug=True)
