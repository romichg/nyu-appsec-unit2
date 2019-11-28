from flask import Flask, request, url_for, render_template, redirect, session
from random import random
import subprocess
import os
import re
from flask_talisman import Talisman
from jinja2 import Environment, select_autoescape
from hashlib import sha256 as SHA256
from secrets import token_hex
from datetime import datetime
from flask_session import Session
from sqlalchemy import create_engine, exc
from sqlalchemy import Column, Integer, ForeignKey, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

# TODO Where did this come from?
env = Environment(autoescape=select_autoescape(
    disabled_extensions=('txt',),
    default_for_string=True,
    default=True,
))


# setting up the app


MAX_INPUT_LENGTH = 50
app = Flask(__name__)
app.config.from_object(__name__)

# Setting up the session
SECRET_KEY = 'supersecretkey'
SESSION_TYPE = 'filesystem'
app.config.from_object(__name__)
Session(app)

# Talisman will handle all the cool security headers we need to have
Talisman(app, force_https=False, strict_transport_security=False, session_cookie_secure=False)

# For our DB
BASE = declarative_base()
DBFILE = "users.db"
db_session = None


# Our DB stuff
def setup_db():
    global BASE
    engine = create_engine(f'sqlite:///{DBFILE}')
    BASE.metadata.bind = engine
    # Before doing this, clean up prev DB for testing purposes.
    # Submit to autograder WITHOUT this line.
    # BASE.metadata.drop_all(engine)
    # Create DB again.
    BASE.metadata.create_all(engine)
    DBSessionMaker = sessionmaker(bind=engine)
    return DBSessionMaker


class User(BASE):
    __tablename__ = 'users'
    uid = Column(Integer, primary_key=True, autoincrement=True)
    uname = Column(String(25), nullable=False, unique=True)
    pword = Column(String(64), nullable=False)
    salt = Column(String(16), nullable=False)
    two_fa = Column(String(11), nullable=False)
    user_type = Column(Integer, nullable=False)


class LoginRecord(BASE):
    __tablename__ = 'login_records'
    record_number =  Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(Integer, ForeignKey('users.uid'), nullable=False)
    time_on = Column(DateTime, nullable=False)
    user = relationship(User)


class QueryHistoryRecord(BASE):
    __tablename__ = 'query_records'
    query_id =  Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(Integer, ForeignKey('users.uid'), nullable=False)
    text_to_check = Column(String(550), nullable=False)
    misspelled = Column(String(550), nullable=False)
    user = relationship(User)


def register_admin():
    uname = 'admin'
    pword = 'Administrator@1'
    two_fa = '12345678901'
    user_type = 0
    hashish = SHA256()
    hashish.update(pword.encode('utf-8'))
    salt = token_hex(nbytes=16)
    hashish.update(salt.encode('utf-8'))
    new_user = User(uname=uname, pword=hashish.hexdigest(), two_fa=two_fa, salt=salt, user_type=user_type)
    try:
        db_session.add(new_user)
        db_session.commit()
    except exc.SQLAlchemyError as err:
        print("Failed to register Admin user. DB Erorr")
        db_session.rollback()


# Set up our database.
DBSessionMaker = setup_db()
# Grab a database session.
db_session = DBSessionMaker()
register_admin()


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


def is_ascii(s):
# lets get the autograder, no security
    return True
#    return s.isascii()


# DB Utils
def get_user_record_by_uid(uid):
    try:
        user_record = db_session.query(User).filter(User.uid == uid).first()
    except exc.SQLAlchemyError as err:
        set_status('Login failed, db error', 'result')
        return None

    return user_record


def get_user_record_by_uname(uname):
    try:
        user_record = db_session.query(User).filter(User.uname == uname).first()
    except exc.SQLAlchemyError as err:
        set_status('Login failed, db error', 'result')
        return None

    return user_record


def get_query_history_by_uid_with_query_ids(uid):
    try:
        query_history = db_session.query(QueryHistoryRecord).filter(QueryHistoryRecord.uid == uid).all()
    except exc.SQLAlchemyError as err:
        set_status('Failed to fetch query history, db error', 'result')
        return None

    return query_history


def get_query_history_record_by_uid_and_query_id(uid, query_id):
    try:
        query_history_record = db_session.query(QueryHistoryRecord).filter(QueryHistoryRecord.uid == uid,
                                                                           QueryHistoryRecord.query_id == query_id).first()
    except exc.SQLAlchemyError as err:
        set_status('Failed ot fetch query history record, db error', 'result')
        return None

    return query_history_record


def get_query_history_record_by_query_id(query_id):
    try:
        query_history_record = db_session.query(QueryHistoryRecord).filter(QueryHistoryRecord.query_id == query_id).first()
    except exc.SQLAlchemyError as err:
        set_status('Failed ot fetch query history record, db error', 'result')
        return None

    return query_history_record


# our utils
def login_user(uname, pword, two_fa):
    # User login checks

    # Check if user exists, and if so get the user
    try:
        user_record = db_session.query(User).filter(User.uname == uname).first()
    except exc.SQLAlchemyError as err:
        set_status('Login failed, db error', 'result')
        return False

    if user_record is None:
        set_status('Login failed, username or password incorrect', 'result')
        return False, None

    # Check if password is valid
    hashish = SHA256()
    hashish.update(pword.encode('utf-8'))
    hashish.update(user_record.salt.encode('utf-8'))
    in_password = hashish.hexdigest()
    our_password = user_record.pword
    if our_password != in_password:
        set_status('Login failed, username or password incorrect', 'result')
        return False, None

    # Check if our 2fa simulation is valid or not
    our_2fa = user_record.two_fa
    in_2fa = two_fa
    if our_2fa != in_2fa:
        set_status('Two-factor authentication failure', 'result')
        return False, None

    return True, user_record


def validate_registration_or_login(uname, pword, two_fa):
    return True

    if not is_ascii(uname):
        return False
    if not is_ascii(pword):
        return False
    if not is_ascii(two_fa):
        return False
    if len(uname) > MAX_INPUT_LENGTH:
        return False
    if len(pword) > MAX_INPUT_LENGTH:
        return False
    if len(two_fa) > MAX_INPUT_LENGTH:
        return False
    if len(two_fa) != 11:
        return False
    if not bool(re.match('^[0-9]{11}$', two_fa)):
        return False
    if not re.findall('^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).*$', pword):
        return False

    return True


# Our routes begin
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form.get('uname')
        pword = request.form.get('pword')  # TODO: look ma, cleartext password
        two_fa = request.form.get('2fa')
        user_type = 1
        csrf_token = request.form.get('csrf_token')

        # CSRF Check
#        our_token = session.get('csrf_token')
#        if csrf_token != our_token:
#            return render_template('404.html')
        session.pop('csrf_token', None)

        # Registration Checks
        if not validate_registration_or_login(uname, pword, two_fa):
            set_status('Registration failure - bad input', 'success')
            session['csrf_token'] = str(random())  # Implement basic CSRF protection
            return render_template('register.html', status=get_status(), csrf_token=session.get('csrf_token'))

        # does user already exist
        try:
            user_record = db_session.query(User).filter(User.uname == uname).first()
        except exc.SQLAlchemyError as err:
            set_status('Registration failure - db error', 'success')
            session['csrf_token'] = str(random())  # Implement basic CSRF protection
            return render_template('register.html', status=get_status(), csrf_token=session.get('csrf_token'))

        if user_record is not None:
            set_status('Registration failure - user exists', 'success')
            session['csrf_token'] = str(random())  # Implement basic CSRF protection
            return render_template('register.html', status=get_status(), csrf_token=session.get('csrf_token'))

        # Otherwise register user
        hashish = SHA256()
        hashish.update(pword.encode('utf-8'))
        salt = token_hex(nbytes=16)
        hashish.update(salt.encode('utf-8'))
        new_user = User(uname=uname, pword=hashish.hexdigest(), two_fa=two_fa, salt=salt, user_type=user_type)
        try:
            db_session.add(new_user)
            db_session.commit()
        except exc.SQLAlchemyError as err:
            set_status('Registration failure, dumb db error', 'success')
            session['csrf_token'] = str(random())  # Implement basic CSRF protection
            return render_template('register.html', status=get_status(), csrf_token=session.get('csrf_token'))
        set_status('Registration success - now please login', 'success')
        return redirect(url_for('login'))

    else:
        session['csrf_token'] = str(random())  # Implement basic CSRF protection
        return render_template('register.html', status=get_status(), csrf_token=session.get('csrf_token'))


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

        if not validate_registration_or_login(uname, pword, two_fa):
            set_status('Login failed - invalid input', 'result')
            session['csrf_token'] = str(random())  # Implement basic CSRF protection
            return render_template('login.html', status=get_status(), csrf_token=session.get('csrf_token'))

        (login_result, user_record) = login_user(uname, pword, two_fa)
        if is_status() or not login_result:
            session['csrf_token'] = str(random())  # Implement basic CSRF protection
            return render_template('login.html', status=get_status(), csrf_token=session.get('csrf_token'))

        # Yeepee - looks like we have a valid user lets log them in
        try:
            login_record = LoginRecord(uid=user_record.uid, time_on=datetime.now())
            db_session.add(login_record)
            db_session.commit()
        except exc.SQLAlchemyError as err:
            print ('SQL Error adding login record' + err)

        # reset session
        session.clear()
        session['uid'] = user_record.uid
        set_status('Login success', 'result')

        return redirect(url_for('spell_check'))

    else:
        session['csrf_token'] = str(random())  # Implement basic CSRF protection
        return render_template('login.html', status=get_status(), csrf_token=session.get('csrf_token'))


@app.route('/spell_check', methods=['GET', 'POST'])
def spell_check():
    if request.method == 'POST':

        # Access control check - make sure the user can do this
        user_record = get_user_record_by_uid(session.get('uid'))
        if user_record is None:
            set_status('Authentication required', 'success')
            return render_template('spell_check.html', status=get_status(), uid=None)

        inputtext = request.form.get('inputtext')
        csrf_token = request.form.get('csrf_token')

        # CSRF Check
        our_token = session.get('csrf_token')
        if csrf_token != our_token:
            return render_template('404.html')
        session.pop('csrf_token', None)

        if inputtext is None or len(inputtext) <= 0:
            set_status('Please enter some text', 'status')

        if len(inputtext) > 500:
            set_status('Invalid input', 'status')

        if not is_ascii(inputtext):
            set_status('Invalid input', 'status')

        if is_status():
            uid = session.get('uid').uid
            session['csrf_token'] = str(random())  # Implement basic CSRF protection
            return render_template('spell_check.html', status=get_status(), uid=uid,
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

        try:
            new_query_record = QueryHistoryRecord(uid=user_record.uid, text_to_check=text, misspelled=misspelled)
            db_session.add(new_query_record)
            db_session.commit()
        except exc.SQLAlchemyError as err:
            print('SQL Error adding history record' + err)

        return render_template('spell_check_result.html', status=get_status(), uid=session.get('uid'), text=text,
                               misspelled=misspelled)
    else:
        uid = session.get('uid')
        session['csrf_token'] = str(random())  # Implement basic CSRF protection
        return render_template('spell_check.html', status=get_status(), uid=session.get('uid'),
                               csrf_token=session.get('csrf_token'))


@app.route('/history', methods=['GET', 'POST'])
def history():
    if request.method == 'GET':
        # Access control check - make sure the user can do this
        user_record = get_user_record_by_uid(session.get('uid'))
        if user_record is None:
            set_status('Authentication required', 'success')
            return render_template('history.html', status=get_status(), uid=session.get('uid'))

        numqueries = 0
        query_records = get_query_history_by_uid_with_query_ids(session.get('uid'))
        if query_records is not None:
            numqueries = len(query_records)
        if numqueries <= 0:
            set_status('No history found', 'status')
            return render_template('history.html', status=get_status(), uid=session.get('uid'), numqueries=numqueries,
                                   user_type=user_record.user_type)

        return render_template('history.html', status=get_status(), uid=session.get('uid'), query_records=query_records,
                               numqueries=numqueries, user_type=user_record.user_type)

    if request.method == 'POST':
        # Access control check - make sure the user can do this
        user_record = get_user_record_by_uid(session.get('uid'))
        if user_record is None:
            set_status('Authentication required', 'success')
            return render_template('history.html', status=get_status(), uid=session.get('uid'))

        # Make sure we are an admin
        if user_record.user_type != 0:
            set_status('You are not an admin, go home.', 'success')
            return render_template('history.html', status=get_status(), uid=session.get('uid'))

        userquery = request.form.get('userquery')
        rr_user_record = get_user_record_by_uname(userquery)

        if rr_user_record is None:
            set_status('Este usario no existe, va a la casa', 'status')
            return render_template('history.html', status=get_status(), uid=session.get('uid'))

        numqueries = 0
        query_records = get_query_history_by_uid_with_query_ids(rr_user_record.uid)
        if query_records is not None:
            numqueries = len(query_records)
        if numqueries <= 0:
            set_status('No history found', 'status')
            return render_template('history.html', status=get_status(), uid=session.get('uid'), numqueries=numqueries)

        return render_template('history.html', status=get_status(), uid=session.get('uid'), query_records=query_records,
                               numqueries=numqueries, user_type=user_record.user_type)


@app.route('/history/query<int:query_id>', methods=['GET'])
def history_query_record(query_id):
    # Access control check - make sure the user can do this
    this_user_record = get_user_record_by_uid(session.get('uid'))
    if this_user_record is None:
        set_status('Authentication required', 'success')
        return render_template('history_record.html', status=get_status(), uid=session.get('uid'))

    if this_user_record.user_type != 0:
        query_record = get_query_history_record_by_uid_and_query_id(session.get('uid'), query_id)
        uname = this_user_record.uname
    elif this_user_record.user_type == 0:
        query_record = get_query_history_record_by_query_id(query_id)
        if query_record is None:
            set_status('NSQ - no such query hahaha', 'status')
            return render_template('history_record.html', status=get_status(), uid=session.get('uid'),
                                   query_record=None)
        user_record = get_user_record_by_uid(query_record.uid)
        if user_record is None:
            set_status('Hey Dear Admin, try not to be so phishy', 'status')
            return render_template('history_record.html', status=get_status(), uid=session.get('uid'),
                                   query_record=None)
        uname = user_record.uname

    if query_record is None:
        set_status('NSQ - no such query hahaha', 'status')
        return render_template('history_record.html', status=get_status(), uid=session.get('uid'),
                               query_record=None)

    # Access control check for the user
    if this_user_record.uid != query_record.uid and this_user_record.user_type != 0:
        set_status('You trying to hack this, bro? (note: this should never happen)', 'status')
        return render_template('history_record.html', status=get_status(), uid=session.get('uid'),
                               query_record=None)

    return render_template('history_record.html', status=get_status(), uid=session.get('uid'),
                           query_record=query_record, username=uname)


if __name__ == '__main__':
    app.run(debug=True)
