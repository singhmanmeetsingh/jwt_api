from flask import Flask ,request,jsonify,make_response
import os
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
import datetime
from functools import wraps
basedir = os.path.abspath(os.path.dirname(__file__))

app=Flask(__name__)

app.config['SECRET_KEY']='sidhumoosewala'

app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///'+os.path.join(basedir,'todo.db')

db=SQLAlchemy(app)

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    public_id=db.Column(db.String(50),unique=True)
    name=db.Column(db.String(50))
    password=db.Column(db.String(80))
    admin=db.Column(db.Boolean)

class Todo(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    text=db.Column(db.String(50))
    complete=db.Column(db.Boolean)
    user_id=db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token =None

        if 'x-access-token'  in request.headers:
            token=request.headers['x-access-token']

        if not token:
            return jsonify({'message':'Token missinf'}),401

        try:
            data=jwt.decode(token,app.config['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message':'token invalid'})
        return f(current_user,*args,**kwargs)

    return decorated



@app.route('/user' ,methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message':'cannot perform function'})

    users=User.query.all()
    output=[]
    for user in users:
        user_data={}
        user_data['publid_id']=user.public_id
        user_data['name']=user.name
        user_data['password']=user.password
        user_data['admin']=user.admin
        output.append(user_data)
    return jsonify({'users': output})


@app.route('/user/<public_id>' ,methods=['GET'])
@token_required
def get_one_user(current_user,public_id):

    if not current_user.admin:
        return jsonify({'message':'cannot perform function'})

    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No User Found'})
    user_data={}
    user_data['publid_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    return jsonify({'user':user_data})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message':'cannot perform function'})

    data=request.get_json()
    hashed_password=generate_password_hash(data['password'],method='sha256')
    new_user=User(public_id=str(uuid.uuid4()),name=data['name'],password=hashed_password,admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message':'New User Created'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user,public_id):

    if not current_user.admin:
        return jsonify({'message':'cannot perform function'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No User Found'})
    user.admin = True
    db.session.commit()
    return jsonify({'message':'User Have Been Promaoted'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):

    if not current_user.admin:
        return jsonify({'message':'cannot perform function'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No User Found'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message':'deleted'})



@app.route('/login')
def login():
    auth=request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not Verify',401,{'WWW-Authenticate':'Basic realm="login Required!'})

    user=User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not Verify',401,{'WWW-Authenticate':'Basic realm="login Required!'})

    if check_password_hash(user.password,auth.password):
        token=jwt.encode({'public_id':user.public_id , 'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)},app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not Verify', 401,{'WWW-Authenticate': 'Basic realm="login Required!'})





@app.route('/todo' ,methods=['GET'])
@token_required
def get_all_todos(current_user):
    todos=Todo.query.filter_by(user_id=current_user.id).all()

    output=[]

    for todo in todos:
        todo_data={}
        todo_data['id']=todo.id
        todo_data['text']=todo.text
        todo_data['complete']=todo.complete
        output.append(todo_data)

    return jsonify({"todo": output})


@app.route('/todo/<todo_id>',methods=['GET'])
@token_required
def get_one_todo(current_user,todo_id):

    todo=Todo.query.filter_by(id=todo_id,user_id=current_user.id).first()

    if not todo:
        return jsonify({'message':'no todo found'})

    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete



    return jsonify({'todo':todo_data})

@app.route('/todo',methods=['POST'])
@token_required
def create_todo(current_user):
    data=request.get_json()
    new_todo=Todo(text=data['text'],complete=False,user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({'message':'todo created'})


@app.route('/todo/<todo_id>',methods=['PUT'])
@token_required
def complete_todo(current_user,todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'no todo found'})

    todo.complete=True
    db.session.commit()
    return jsonify({'message':'task completed'})

@app.route('/todo/<todo_id>',methods=['DELETE'])
@token_required
def delete_todo(current_user,todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'message': 'no todo found'})

    db.session.delete(todo)
    db.session.commit()
    return jsonify({"message":"todo  deleted"})

#


