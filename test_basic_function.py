import requests
from bs4 import BeautifulSoup

server_address = 'http://127.0.0.1:1337'


def get_element_by_id(html, our_id):
    soup = BeautifulSoup(html, 'html.parser')
    r = soup.find(id=our_id)
    return r


def get_csrf_token(url, session=None):
    if session is None:
        session = requests.session()
        session.close()  # close any previous session if exist

    initial_get = session.get(url)
    csrf_token_elemnt = get_element_by_id(initial_get.text, 'csrf_token')
    csrf_token = csrf_token_elemnt.attrs['value']

    return csrf_token


def spell_check(text_to_check, misspelled, csrf_token, session=None):
    url = server_address + '/spell_check'
    if session is None:
        session = requests.session()
        session.close()  # close any previous session if exist

    inputdata = {'inputtext': text_to_check, 'csrf_token': csrf_token}
    r = session.post(url, data=inputdata)
    rcvd_misspelled = get_element_by_id(r.text, 'misspelled')
    if rcvd_misspelled is None:
        print('Unable to find id=misspelled in the response, likely something went wrong')
        return {'result': False, 'session': session}

    rcvd_text_to_check = get_element_by_id(r.text, 'textout')
    if rcvd_text_to_check is None:
        print('Unable to find id=text in the response, likely something went wrong')
        return {'result': False, 'session': session}

    for word in misspelled:
        if word not in rcvd_misspelled.text:
            print('Not all the misspelled words are returned')
            return {'result': False, 'session': session}

    if rcvd_text_to_check.text != text_to_check:
        print('Returned text is not the same one as we provided')
        return {'result': False, 'session': session}

    return {'result': True, 'session': session}


def register(username, password, two_fa, session=None):
    url = server_address + '/register'
    if session is None:
        session = requests.session()
        session.close()  # close any previous session if exist

    creds = {'uname': username, 'pword': password, '2fa': two_fa}
    r = session.post(url, data=creds)
    result = get_element_by_id(r.text, 'success')
    if result is None:
        print('Unable to find id=result in the response, likely we are not registered')
        return {'result': False, 'session': session}

    if 'success' in result.text:
        # Server said registration successful we will assume we are logged in
        return {'result': True, 'session': session}
    elif 'failure' in result.text:
        # Server responded with a failure
        return {'result': False, 'explicit_failure': True, 'session': session}
    else:
        # Server doesn't respond with indication of registration success, we assume we are not registered
        return {'result': False, 'explicit_failure': False, 'session': session}


def login(username, password, two_fa, session=None):
    url = server_address + '/login'
    if session is None:
        session = requests.session()
        session.close()  # close any previous session if exist

    creds = {'uname': username, 'pword': password, '2fa': two_fa}
    r = session.post(url, data=creds)
    result = get_element_by_id(r.text, 'result')
    if result is None:
        print('Unable to find id=result in the response, likely we are not logged in')
        return {'result': False, 'session': session}

    if 'success' in result.text:
        # Server said login successful we will assume we are logged in
        return {'result': True, 'session': session}
    else:
        # Server doesn't respond with indication of login success, we assume we are not
        return {'result': False, 'session': session}


def test_login_page_exists():
    req = requests.get(server_address + '/login')
    assert req.status_code == 200, "Server down, status code not 200"


def test_register_page_exists():
    req = requests.get(server_address + '/register')
    assert req.status_code == 200, "Server down, status code not 200"


def test_spell_check_page_exists():
    req = requests.get(server_address + '/spell_check')
    assert req.status_code == 200, "Server down, status code not 200"
    

def test_valid_login_default_credential():  # look ma, we have a hard coded user it is vewy secure to do that
    r = login('roman', 'SuperSecureLong1!PW@', '9876543210')
    assert r['result'] is True, "Failed to login"


def test_register_valid_user():
    r = register('3dafve', 'MyStrongPW123!', '1234567890')
    assert r['result'] is True, "Failed to register valid user"
    

def test_login_registered_user():
    r = login('3dafve', 'MyStrongPW123!', '1234567890')
    assert r['result'] is True, "Failed to login"


def test_spell_check_flow():
    r1 = register('fulltest', 'MyStrongPW123!', '1234567890')
    assert r1['result'] is True, "Failed to register"
    r2 = login('fulltest', 'MyStrongPW123!', '1234567890')
    assert r2['result'] is True, "Failed to login"
    csrf_token = get_csrf_token(server_address + '/login', r2['session'])
    r3 = spell_check('my uncle, hgh ideals inspore him but when past joking he fell ill', ['hgh', 'inspore'], csrf_token, r2['session'])
    assert r3['result'] is True, "Failed to spell check"

def test_spell_check_without_csrf():
    r1 = register('fulltestNOCSRF', 'MyStrongPW123!', '1234567890')
    assert r1['result'] is True, "Failed to register"
    r2 = login('fulltestNOCSRF', 'MyStrongPW123!', '1234567890')
    assert r2['result'] is True, "Failed to login"
    csrf_token = ''
    r3 = spell_check('my uncle, hgh ideals inspore him but when past joking he fell ill', ['hgh', 'inspore'], csrf_token, r2['session'])
    assert r3['result'] is False, "Failed to spell check"


def test_login_invalid_user():
    r = login('noexist', 'MyStrongPW123!', '1234567890')
    assert r['result'] is False, "Failed to login"


def test_login_invalid_password():
    r = login('3dafve', 'MyStrongPW123@', '1234567890')
    assert r['result'] is False, "Failed to login"


def test_login_invalid_two_fa():
    r = login('3dafve', 'MyStrongPW123!', '9876543210')
    assert r['result'] is False, "Failed to login"


def test_register_non_numeric_two_fa():
    r = register('3dagg', 'MyStrongPW123!', 'abcd')
    assert r['result'] is False, "Able to register with non-numeric 2fa"


def test_register_empty_password():
    r = register('uhadd', '', '9876543210')
    assert r['result'] is False, "Able to register with empty password"


def test_register_short_password():
    r = register('vagdd', 'Abcd1f!', '9876543210')
    assert r['result'] is False, "Able to register with short password"


def test_register_no_cap_password():
    r = register('vagda', 'abcde!gh2', '9876543210')
    assert r['result'] is False, "Able to register with no cap password"


def test_register_no_special_password():
    r = register('vagdb', 'abcdeFgh2', '9876543210')
    assert r['result'] is False, "Able to register with no special char password"


def test_register_no_number_password():
    r = register('vagdc', 'abcdeFgh!', '9876543210')
    assert r['result'] is False, "Able to register with no number char password"


def test_register_and_login_big_input():
    r = register('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'abcdeFgh!', '9876543210')
    assert r['result'] is False, "Register with super long name"
    r = register('superlongpw', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaFgh!', '9876543210')
    assert r['result'] is False, "Register with super long pw"
    r = register('superlong2fa', 'MySecurePW1!', '12345678901')
    assert r['result'] is False, "Register with 2fa longer than 10 digits"
    r = login('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'abcdeFgh!', '9876543210')
    assert r['result'] is False, "Login with super long name"
    r = login('superlongpw', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaFgh!', '9876543210')
    assert r['result'] is False, "Login with super long pw"
    r = login('superlong2fa', 'MySecurePW1!', '12345678901')
    assert r['result'] is False, "Login with 2fa longer than 10 digits"

