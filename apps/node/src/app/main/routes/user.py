import logging
from secrets import token_hex
from json import dumps, loads
from json.decoder import JSONDecodeError
from datetime import datetime, timedelta

import jwt
from bcrypt import hashpw, checkpw, gensalt
from syft.codes import RESPONSE_MSG
from flask import request, Response
from flask import current_app as app
from werkzeug.security import generate_password_hash, check_password_hash

from ..core.exceptions import (
    PyGridError,
    UserNotFoundError,
    RoleNotFoundError,
    AuthorizationError,
    MissingRequestKeyError,
    InvalidCredentialsError
)
from .. import main_routes
from ..users import Role, User
from ... import db
from .auth import token_required

def model_to_json(model):
    """Returns a JSON representation of an SQLAlchemy-backed object."""
    json = {}
    for col in model.__mapper__.attrs.keys():
        if col != "hashed_password" and col != "salt":
            json[col] = getattr(model, col)

    return json


def identify_user(request):
    private_key = request.headers.get("private-key")
    if private_key is None:
        raise MissingRequestKeyError

    usr = db.session.query(User).filter_by(private_key=private_key).one_or_none()
    if usr is None:
        raise UserNotFoundError

    usr_role = db.session.query(Role).get(usr.role)
    if usr_role is None:
        raise RoleNotFoundError

    return usr, usr_role


@main_routes.route('/users', methods=['POST'])
def signup_user():
    status_code = 200  # Success
    response_body = {}
    usr_role = None
    usr = None

    try:
        usr, usr_role = identify_user(request)
    except Exception as e:
        logging.warning("Existing user could not be linked", exc_info=e)

    try:
        data = loads(request.data)
        password = data.get('password')
        email = data.get('email')
        role = data.get('role')

        if email is None or password is None:
            raise MissingRequestKeyError
     
        password = password.encode('UTF-8')
        private_key = token_hex(32)
        salt =gensalt(rounds=12)
        hashed = hashpw(password, salt)
        hashed = hashed.decode('UTF-8')
        salt = salt.decode('UTF-8')
        no_user = len(db.session.query(User).all()) == 0

        if no_user:
            role = db.session.query(Role.id).filter_by(name="Owner").first()[0]
            new_user = User(email=email, hashed_password=hashed,
                            salt=salt, private_key=private_key, role=role)
        elif (role is not None and usr_role is not None and
              usr_role.can_create_users):
            new_user = User(email=email, hashed_password=hashed,
                            salt=salt, private_key=private_key, role=role)
        else:
            role = db.session.query(Role.id).filter_by(name="User").first()[0]
            new_user = User(email=email, hashed_password=hashed,
                            salt=salt, private_key=private_key, role=role)

        db.session.add(new_user)
        db.session.commit()

        user = model_to_json(new_user)
        user["role"] = db.session.query(Role).get(user["role"])
        user["role"] = model_to_json(user["role"])
        user.pop('hashed_password', None)
        user.pop('salt', None)
            
        response_body = {RESPONSE_MSG.SUCCESS: True, "user": user}

    except RoleNotFoundError as e:
        status_code = 404  # Resource not found
        response_body[RESPONSE_MSG.ERROR] = str(e)
        logging.warning("User not found in post-role", exc_info=e)
    except (TypeError, MissingRequestKeyError, PyGridError, JSONDecodeError) as e:
        status_code = 400  # Bad Request
        response_body[RESPONSE_MSG.ERROR] = str(e)
    except Exception as e:
        status_code = 500  # Internal Server Error
        response_body[RESPONSE_MSG.ERROR] = str(e)

    return Response(
        dumps(response_body), status=status_code, mimetype="application/json"
    )


@main_routes.route('/users/login', methods=['POST'])
def login_user():
    status_code = 200  # Success
    response_body = {}
    
    try:
    
        data = loads(request.data)
        email = data.get('email')
        password = data.get('password')
        if email is None or password is None:
            raise MissingRequestKeyError

        password = password.encode('UTF-8')
        private_key = request.headers.get("private-key")
        if private_key is None:
            raise MissingRequestKeyError

        usr = User.query.filter_by(email=email,
                                   private_key=private_key).first()
        if usr is None:
            raise InvalidCredentialsError       

        hashed = usr.hashed_password.encode('UTF-8')
        if checkpw(password, hashed):
            token = jwt.encode({'id': usr.id},
                                app.config['SECRET_KEY'])
            response_body = {RESPONSE_MSG.SUCCESS: True,
                             'token' : token.decode('UTF-8')}
        else:
            raise InvalidCredentialsError       

    except InvalidCredentialsError as e:
        status_code = 403  # Unathorized
        response_body[RESPONSE_MSG.ERROR] = str(e)
        logging.warning("User credentials are invalid", exc_info=e)
    except (RoleNotFoundError, UserNotFoundError) as e:
        status_code = 404  # Resource not found
        response_body[RESPONSE_MSG.ERROR] = str(e)
        logging.warning("User not found in post-role", exc_info=e)
    except (TypeError, MissingRequestKeyError, PyGridError, JSONDecodeError) as e:
        status_code = 400  # Bad Request
        response_body[RESPONSE_MSG.ERROR] = str(e)
    except Exception as e:
        status_code = 500  # Internal Server Error
        response_body[RESPONSE_MSG.ERROR] = str(e)

    return Response(
        dumps(response_body), status=status_code, mimetype="application/json"
    )


@main_routes.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    status_code = 200  # Success
    response_body = {}
    
    try:
        private_key = request.headers.get("private-key")
        if private_key is None:
            raise MissingRequestKeyError
   
        if private_key != current_user.private_key:
            raise InvalidCredentialsError       

        usr_role = Role.query.get(current_user.role)
        if usr_role is None:
            raise RoleNotFoundError

        if not usr_role.can_triage_jobs:
            raise AuthorizationError

        users = [model_to_json(user) for user in User.query.all()]

        response_body = {RESPONSE_MSG.SUCCESS: True,
                         'users' : users}

    except (InvalidCredentialsError, AuthorizationError) as e:
        status_code = 403  # Unathorized
        response_body[RESPONSE_MSG.ERROR] = str(e)
        logging.warning("User credentials are invalid", exc_info=e)
    except (RoleNotFoundError, UserNotFoundError) as e:
        status_code = 404  # Resource not found
        response_body[RESPONSE_MSG.ERROR] = str(e)
        logging.warning("User not found in get-roles", exc_info=e)
    except (TypeError, MissingRequestKeyError, PyGridError, JSONDecodeError) as e:
        status_code = 400  # Bad Request
        response_body[RESPONSE_MSG.ERROR] = str(e)
    except Exception as e:
        status_code = 500  # Internal Server Error
        response_body[RESPONSE_MSG.ERROR] = str(e)

    return Response(
        dumps(response_body), status=status_code, mimetype="application/json"
    )
