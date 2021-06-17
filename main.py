# Local modules
import app_secrets
import constants

# For app
from flask import Flask, request, jsonify, redirect, render_template, session, url_for, _request_ctx_stack
import requests
import json
import re

# For GCP Datastore
from google.cloud import datastore

# For Auth0
from authlib.integrations.flask_client import OAuth
from urllib.parse import urlencode
from urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt
from functools import wraps
from os import environ as env
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv, find_dotenv

# Instantiate Flask app
app = Flask(__name__)

# Instantiate Datastore client
client = datastore.Client()

# Secret key used for session management
app.secret_key = app_secrets.secret_key

# Error types
bad_request_error_400 = {'Error': 'The request object is missing at least one of the required attributes'}
id_error_400 = {'Error': 'Cannot change id of an entity'}
unauthenticated_error_401 = {'Error': 'The user cannot be authenticated'}
unauthorized_error_403 = {'Error': 'The user is not authorized to view/modify this entity'}
assignment_error_403 = {'Error': 'The load is already assigned'}
uniqueness_error_403 = {'Error': 'The boat name is not unique'}
not_found_error_404 = {'Error': 'No entity with this id exists'}
method_error_405 = {'Error': 'The request method is not allowed'}
server_type_error_406 = {'Error': 'Server cannot produce acceptable response type'}

CLIENT_ID = app_secrets.client_id
CLIENT_SECRET = app_secrets.client_secret
DOMAIN = app_secrets.domain
# CALLBACK_URL = 'http://127.0.0.1:8080/callback'
CALLBACK_URL = 'https://cs493-project-tonv.wm.r.appspot.com/callback'
ALGORITHMS = ['RS256']

oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url='https://' + DOMAIN,
    access_token_url='https://' + DOMAIN + '/oauth/token',
    authorize_url='https://' + DOMAIN + '/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response
    
def verify_jwt(request):
    try:
        auth_header = request.headers['Authorization'].split();
    except:
        raise AuthError({'code': 'invalid_header',
                        'description':
                            'Invalid header. '
                            'Invalid Authorization Token'}, 401)

    token = auth_header[1]
    jsonurl = urlopen('https://'+ DOMAIN+'/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())

    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({'code': 'invalid_header',
                        'description':
                            'Invalid header. '
                            'Use an RS256 signed JWT Access Token'}, 401)
    
    if unverified_header['alg'] == 'HS256':
        raise AuthError({'code': 'invalid_header',
                        'description':
                            'Invalid header. '
                            'Use an RS256 signed JWT Access Token'}, 401)

    rsa_key = {}

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }

    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer='https://'+ DOMAIN+'/'
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({'code': 'token_expired',
                            'description': 'token is expired'}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({'code': 'invalid_claims',
                            'description':
                                'incorrect claims,'
                                ' please check the audience and issuer'}, 401)
        except Exception:
            raise AuthError({'code': 'invalid_header',
                            'description':
                                'Unable to parse authentication'
                                ' token.'}, 401)
        return payload
    else:
        raise AuthError({'code': 'no_rsa_key',
                            'description':
                                'No RSA key in JWKS'}, 401)

# Beginning of application
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/users', methods=['GET'])
def users():
    if request.method == 'GET':
        # Check Accept header for application/json
        if not request.accept_mimetypes.accept_json:
            return server_type_error_406, 406

        query = client.query(kind=constants.users)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
        output = {"users": results}
        if next_url:
            output["next"] = next_url
        return json.dumps(output)
    else:
        return method_error_405, 405

@app.route('/boats', methods=['POST', 'GET'])
def boats():
    if request.method == 'POST':
        # Check Accept header for application/json
        if not request.accept_mimetypes.accept_json:
            return server_type_error_406, 406

        # Authenticate user
        try:
            payload = verify_jwt(request)
        except:
            return unauthenticated_error_401, 401

        # Get content of request
        content = request.get_json()

        # Check for required attributes in request
        if ('name' not in content
            or content['name'] is None
            or 'type' not in content
            or content['type'] is None
            or 'length' not in content
            or content['length'] is None):
            return bad_request_error_400, 400

        # Check for invalid characters in name and type, invalid digit in length
        if (re.match('^[\w\d _-]*$', str(content['name']))
            and re.match('^[\w\d _-]*$', str(content['type']))
            and content['length'].isdigit()
            and int(content['length']) > 0):

            # Create new boat if passed validation
            new_boat = datastore.entity.Entity(key=client.key(constants.boats))
            new_boat.update({
                'name': content['name'], 
                'type': content['type'], 
                'length': content['length'],
                'owner': payload['sub'],
                'loads': []
                })
            client.put(new_boat)
            content['id'] = new_boat.key.id
            content['loads'] = []
            content['self'] = request.url_root + 'boats/' + str(new_boat.key.id)
            return content, 201
        else:
            return bad_request_error_400, 400
    elif request.method == 'GET':
        # Check Accept header for application/json
        if not request.accept_mimetypes.accept_json:
            return server_type_error_406, 406

        try:
            # Authenticate user
            payload = verify_jwt(request)

            # Filter results if user is authenticated
            query = client.query(kind=constants.boats)
            query.add_filter('owner', '=', payload['sub'])
            quantity = len(list(query.fetch()))

            # Set up pagination
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit= q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))

            # Set up next link
            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None

            # Compose response
            for e in results:
                e["id"] = e.key.id
                e['self'] = request.url_root + 'boats/' + str(e.key.id)
            output = {"quantity": quantity, "boats": results}
            if next_url:
                output["next"] = next_url
            return json.dumps(output)
        except:
            return unauthenticated_error_401, 401
    else:
        return method_error_405, 405

@app.route('/boats/<id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def boats_id(id):
    # Get request content
    content = request.get_json()

    # Open up transaction
    with client.transaction():
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)

        if boat is None:
            return not_found_error_404, 404

        if request.method == 'GET':
            # Check Accept header for application/json
            if not request.accept_mimetypes.accept_json:
                return server_type_error_406, 406

            try:
                # Authenticate user
                payload = verify_jwt(request)
                if boat['owner'] == payload['sub']:
                    boat['id'] = str(id)
                    boat['self'] = request.url_root + 'boats/' + str(id)
                    return json.dumps(boat)
                else:
                    return unauthorized_error_403, 403
            except:
                return unauthenticated_error_401, 401
        elif request.method == 'PATCH':
            # Check for id change in request
            if 'id' in content:
                return id_error_400, 400

            # Check Accept header for application/json
            if not request.accept_mimetypes.accept_json:
                return server_type_error_406, 406

            try:
                # Authenticate user
                payload = verify_jwt(request)
                if boat['owner'] == payload['sub']:
                    temp_boat = boat
                    # Check for name in content
                    if 'name' in content and content['name'] is not None:
                        temp_boat['name'] = content['name']
                    # Check for type in content
                    if 'type' in content and content['type'] is not None:
                        temp_boat['type'] = content['type']
                    # Check for length in content
                    if 'length' in content and content['length'] is not None:
                        temp_boat['length'] = content['length']
                    # Update boat attributes
                    boat.update({'name': temp_boat['name'], 'type': temp_boat['type'], 'length': temp_boat['length']})
                    client.put(boat)
                    # Append boat ID and direct link
                    boat['id'] = str(id)
                    boat['self'] = request.url_root + 'boats/' + str(id)
                    return json.dumps(boat)
                else:
                    return unauthorized_error_403, 403
            except:
                return unauthenticated_error_401, 401
        elif request.method == 'PUT':
            # Check for id change in request
            if 'id' in content:
                return id_error_400, 400

            # Check for required attributes
            if ('name' not in content 
                or content['name'] is None
                or 'type' not in content
                or content['type'] is None
                or 'length' not in content 
                or content['length'] is None):
                return bad_request_error_400, 400

            # Check Accept header for application/json
            if not request.accept_mimetypes.accept_json:
                return server_type_error_406, 406
            try:
                # Authenticate user
                payload = verify_jwt(request)
                if boat['owner'] == payload['sub']:
                    # Update boat attributes
                    boat.update({'name': content['name'], 'type': content['type'], 'length': content['length']})
                    client.put(boat)
                    # Append boat ID and direct link
                    boat['id'] = str(id)
                    boat['self'] = request.url_root + 'boats/' + str(id)
                    return json.dumps(boat)
                else:
                    return unauthorized_error_403, 403
            except:
                return unauthenticated_error_401, 401
        elif request.method == 'DELETE':
            try:
                # Authenticate user
                payload = verify_jwt(request)
                if boat['owner'] == payload['sub']:
                    if boat['loads']:
                        for e in boat['loads']:
                            load_key = client.key(constants.loads, int(e))
                            load = client.get(key=load_key)
                            load['carrier'] = None
                            client.put(load)
                        client.delete(boat_key)
                        return '', 204
                    else:
                        client.delete(boat_key)
                        return '', 204
                else:
                    return unauthorized_error_403, 403
            except:
                return unauthenticated_error_401, 401
        else:
            return method_error_405, 405

@app.route('/loads', methods=['POST', 'GET'])
def loads():
    if request.method == 'POST':
        # Check Accept header for application/json
        if not request.accept_mimetypes.accept_json:
            return server_type_error_406, 406

        content = request.get_json()
        # Check for required attributes in request
        if ('volume' not in content
            or 'content' not in content):
            return bad_request_error_400, 400

        new_load = datastore.entity.Entity(key=client.key(constants.loads))
        new_load.update({
            'volume': content['volume'], 
            'content': content['content'],
            'carrier': None,
            'creation_date': '6/6/2021'
            })
        client.put(new_load)
        content['id'] = new_load.key.id
        content['carrier'] = None
        content['creation_date'] = '6/6/2021'
        content['self'] = request.url_root + 'loads/' + str(new_load.key.id)
        return content, 201
    elif request.method == 'GET':
        # Check Accept header for application/json
        if not request.accept_mimetypes.accept_json:
            return server_type_error_406, 406

        query = client.query(kind=constants.loads)
        quantity = len(list(query.fetch()))
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
            e['self'] = request.url_root + 'loads/' + str(e.key.id)
        output = {"quantity": quantity, "loads": results}
        if next_url:
            output["next"] = next_url
        return json.dumps(output)
    else:
        return method_error_405, 405

@app.route('/loads/<id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def loads_id(id):
    # Get request content
    content = request.get_json()

    with client.transaction():
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)

        if load is None:
            return not_found_error_404, 404

        if request.method == 'GET':
            # Check Accept header for application/json
            if not request.accept_mimetypes.accept_json:
                return server_type_error_406, 406

            load['id'] = id
            load['self'] = request.url_root + 'loads/' + str(id)
            return json.dumps(load)
        elif request.method == 'PATCH':
            # Check for id change in request
            if 'id' in content:
                return id_error_400, 400

            # Check Accept header for application/json
            if not request.accept_mimetypes.accept_json:
                return server_type_error_406, 406

            temp_load = load
            # Check for volume in content
            if 'volume' in content and content['volume'] is not None:
                temp_load['volume'] = content['volume']
            # Check for content type in content
            if 'content' in content and content['content'] is not None:
                temp_load['content'] = content['content']
            # Update boat attributes
            load.update({'volume': temp_load['volume'], 'content': temp_load['content']})
            client.put(load)
            # Append boat ID and direct link
            load['id'] = str(id)
            load['self'] = request.url_root + 'loads/' + str(id)
            return json.dumps(load)
        elif request.method == 'PUT':
            # Check for id change in request
            if 'id' in content:
                return id_error_400, 400

            # Check Accept header for application/json
            if not request.accept_mimetypes.accept_json:
                return server_type_error_406, 406

            # Check for required attributes
            if ('volume' not in content 
                or content['volume'] is None
                or 'content' not in content
                or content['content'] is None):
                return bad_request_error_400, 400

            # Check Accept header for application/json
            if not request.accept_mimetypes.accept_json:
                return server_type_error_406, 406

            # Update boat attributes
            load.update({'volume': content['volume'], 'content': content['content']})
            client.put(load)
            # Append boat ID and direct link
            load['id'] = str(id)
            load['self'] = request.url_root + 'boats/' + str(id)
            return json.dumps(load)
        elif request.method == 'DELETE':
            if load['carrier'] is not None:
                boat_key = client.key(constants.boats, int(load['carrier']))
                boat = client.get(key=boat_key)
                if id in boat['loads']:
                    boat['loads'].remove(id)
                    client.put(boat)
            client.delete(load_key)
            return '', 204
        else:
            return method_error_405, 405

@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PATCH', 'DELETE'])
def loads_patch_delete(boat_id, load_id):
    assignment_error = {'Error': 'The load is already assigned'}
    with client.transaction():
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)

        if boat is None:
            return not_found_error_404, 404
        
        if load is None:
            return not_found_error_404, 404
        
        if request.method == 'PATCH':
            if load["carrier"] is None:
                load['carrier'] = boat_id
                boat['loads'].append(load_id)
                client.put(load)
                client.put(boat)
                return '', 200
            else:
                return assignment_error, 403
        elif request.method == 'DELETE':
            load['carrier'] = None
            if load_id in boat['loads']:
                boat['loads'].remove(load_id)
                client.put(load)
                client.put(boat)
                return '', 204
            else:
                return not_found_error_404, 404
        else:
            return method_error_405, 405
                
@app.route('/api', methods=['POST'])
def api():
    if request.method=='POST':
        content = request.get_json()
        username = content['username']
        password = content['password']
        body = {'grant_type':'password',
                'username':username,
                'password':password,
                'client_id':CLIENT_ID,
                'client_secret':CLIENT_SECRET
            }
        headers = { 'content-type': 'application/json' }
        url = 'https://' + DOMAIN + '/oauth/token'
        r = requests.post(url, json=body, headers=headers)
        return r.text, 200, {'Content-Type':'application/json'}
    else:
        return method_error_405, 405

@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=CALLBACK_URL)

@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('index', _external=True), 'client_id': CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

@app.route('/callback')
def callback_handling():
    # Handle response from token endpoint
    token = auth0.authorize_access_token()['id_token']
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    # Check for user in Datastore
    new_user = datastore.entity.Entity(key=client.key(constants.users))
    new_user.update({'auth_id': userinfo['sub'], 'email': userinfo['email']})
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    auth_ids = []
    for e in results:
        auth_ids.append(e['auth_id'])

    if userinfo['sub'] not in auth_ids:
        # Create user in Datastore if sub value doesn't exist
        client.put(new_user)
        session['ds_id'] = new_user.key.id
    else:
        # Find Datastore id of user if sub value exists
        pos = auth_ids.index(userinfo['sub'])
        session['ds_id'] = results[pos].key.id

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['jwt'] = token
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/dashboard')
    
@app.route('/dashboard')
#@requires_auth
def dashboard():
    return render_template('dashboard.html',
                            ds_id=session['ds_id'],
                            jwt=session['jwt'])

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)