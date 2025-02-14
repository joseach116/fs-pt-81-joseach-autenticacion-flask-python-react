"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""

from flask_sqlalchemy import SQLAlchemy
from flask import request, jsonify, Blueprint, Flask
from api.models import User, db
from api.utils import APIException
from flask_jwt_extended import get_jwt_identity, jwt_required, JWTManager, create_access_token
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash


bcrypt = Bcrypt()
api = Blueprint('api', __name__)
CORS(api)

@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():
    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }
    return jsonify(response_body), 200


@api.route('/signup', methods=['POST'])
def user_signup():
    try:
        email = request.json.get("email", None)
        password = request.json.get("password", None)

        if not email or not password:
            return jsonify({"msg": "Email and password are required"}), 400

        user = User(
            email=email,
            password=bcrypt.generate_password_hash(password).decode('utf-8'),
            is_active=True
        )
        
        db.session.add(user)
        db.session.commit()

        response_body = {
            "message": "Register Ok",
            "id": user.id,
            "email": user.email
        }
        return jsonify(response_body), 201
    except Exception as e:
        raise APIException(status_code=500, message=str(e))


@api.route("/login", methods=["POST"])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    if not email or not password:
        return jsonify({"msg": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"msg": "Invalid email or password"}), 401
    
    access_token = create_access_token(identity=email)
    return jsonify(access_token=access_token), 201


@api.route("/private", methods=["GET"])
@jwt_required()
def protected():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()

    if not user:
        return jsonify({"msg": "User not found"}), 404

    return jsonify(logged_in_as=current_user_email), 200


@api.errorhandler(APIException)
def handle_api_exception(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


if __name__ == "__main__":
    api.run()