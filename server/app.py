#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


# ---------- SIGNUP ----------
class Signup(Resource):
    def post(self):
        data = request.get_json()

        try:
            new_user = User(
                username=data['username'],
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )
            new_user.password_hash = data['password']  # hash the password
            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id
            return make_response(new_user.to_dict(), 201)

        except (KeyError, IntegrityError, ValueError):
            db.session.rollback()
            return make_response({"errors": ["validation errors"]}, 422)


# ---------- CHECK SESSION ----------
class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = db.session.get(User, user_id)
            if user:
                return make_response(user.to_dict(), 200)
        return make_response({"error": "Unauthorized"}, 401)


# ---------- LOGIN ----------
class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data.get('username')).first()

        if user and user.authenticate(data.get('password')):
            session['user_id'] = user.id
            return make_response(user.to_dict(), 200)

        return make_response({"error": "Invalid username or password"}, 401)


# ---------- LOGOUT ----------
class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session.pop('user_id')
            return make_response('', 204)
        return make_response({"error": "Unauthorized"}, 401)


# ---------- RECIPES ----------
class RecipeIndex(Resource):
    def get(self):
        if not session.get('user_id'):
            return make_response({"error": "Unauthorized"}, 401)

        recipes = [r.to_dict() for r in Recipe.query.all()]
        return make_response(recipes, 200)

    def post(self):
        if not session.get('user_id'):
            return make_response({"error": "Unauthorized"}, 401)

        data = request.get_json()
        try:
            new_recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=session['user_id']
            )
            db.session.add(new_recipe)
            db.session.commit()
            return make_response(new_recipe.to_dict(), 201)

        except (KeyError, IntegrityError, ValueError):
            db.session.rollback()
            return make_response({"errors": ["validation errors"]}, 422)


# ---------- REGISTER RESOURCES ----------
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
