from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
from werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps
import openpyxl

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your secret key'
# database name
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///parsing.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# creates SQLALCHEMY object
db = SQLAlchemy(app)

# Database ORMs
class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique = True)
    password = db.Column(db.String(80))


# Database of file
class parsing(db.Model):
    id= db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(20))
    age = db.Column(db.Integer())


# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id = data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid !!'}), 401
        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods =['GET'])
@token_required
def get_all_users(current_user):
    users = User.query.all()
    return ('helloo')


@app.route('/pras',methods = ['POST'])
@token_required
def pras(current_user):
    data = request.files['file']
    workbook = openpyxl.load_workbook(data)
    print(workbook)
    sheet = workbook.active

    for row in sheet.iter_rows(min_row=True, values_only = True):
        name, age = row
        data2 = parsing(name = name, age=age)
        db.session.add(data2)
        db.session.commit()

    return ('msg : uploaded')



@app.route('/create',methods = ['POST'])
@token_required
def add(current_user):
    if request.method == 'POST':
        name = request.json['name']
        age = request.json['age']
        new_user = parsing(name = name, age=age)
        db.session.add(new_user)
        db.session.commit()

    return ('data added')


@app.route('/update', methods = ['POST'])
@token_required
def update(current_user):
    if request.method == 'POST':
        id= request.json['id']
        name = request.json['name']
        par = parsing.query.filter_by(id=id).first()
        print(par.name)
        par.name = name
        db.session.add(par)
        db.session.commit()
    return ('data : modified')


@app.route('/delete', methods = ['DELETE'])
@token_required
def delete(current_user):
    if request.method == 'DELETE':
        id= request.json['id']
        par = parsing.query.filter_by(id=id).first()
        db.session.delete(par)
        db.session.commit()
    return ('data : deleted')


# route for logging user in
@app.route('/login', methods =['POST'])
def login():
    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):
        return make_response(
            'Could not verify',
            401,
            {'msg' : "Login required !!"}
        )

    user = User.query\
        .filter_by(email = auth.get('email'))\
        .first()

    if not user:
        return make_response(
            'Could not verify',
            401,
            {'msg' : "User does not exist !!"}
        )

    # if check_password_hash(user.password, auth.get('password')):
    if user.password == auth.get('password'):
        token = jwt.encode({
            'public_id': user.public_id,
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
        }, app.config['SECRET_KEY'])

        return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
    return make_response(
        'Could not verify',
        403,
        {'msg' : "Wrong Password !!"}
    )

# signup route
@app.route('/signup', methods =['POST'])
def signup():
    data = request.form

    name, email = data.get('name'), data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email = email).first()
    if not user:
        user = User(
            public_id = str(uuid.uuid4()),
            name = name,
            email = email,
            # password = generate_password_hash(password)
            password = password
        )
        db.session.add(user)
        db.session.commit()

        return make_response('Successfully registered.', 201)
    else:
        return make_response('User already exists. Please Log in.', 202)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug = True)