from functools import wraps

from flask import jsonify, request
from flask import current_app as app
import jwt

from ..users import User
from ... import db


def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
      token = request.headers.get('token')
      if token is None:
          return jsonify({'message': 'a valid token is missing'})

      try:
         data = jwt.decode(token, app.config['SECRET_KEY'])
         current_user = User.query.get(data['id'])
      except:
         return jsonify({'message': 'token is invalid'})

      return f(current_user, *args, **kwargs)
   return decorator
