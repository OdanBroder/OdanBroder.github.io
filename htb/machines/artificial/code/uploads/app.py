from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
import tensorflow as tf
import hashlib
import uuid
import numpy as np
import io
from contextlib import redirect_stdout
import hashlib

app = Flask(__name__)
app.secret_key = "Sup3rS3cr3tKey4rtIfici4L"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'models'

db = SQLAlchemy(app)

MODEL_FOLDER = 'models'
os.makedirs(MODEL_FOLDER, exist_ok=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    models = db.relationship('Model', backref='owner', lazy=True)

class Model(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'h5'

def hash(password):
 password = password.encode()
 hash = hashlib.md5(password).hexdigest()
 return hash

@app.route('/')
def index():
    if ('user_id' in session):
        username = session['username']
        if (User.query.filter_by(username=username).first()):
            return redirect(url_for('dashboard'))

    return render_template('index.html')

@app.route('/static/requirements.txt')
def download_txt():
    try:
        pdf_path = './static/requirements.txt'  # Adjust path as needed
        
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name='requirements.txt',  # Name for downloaded file
            mimetype='application/text'
        )
    except FileNotFoundError:
        return "requirements file not found", 404


@app.route('/static/Dockerfile')
def download_dockerfile():
    try:
        pdf_path = './static/Dockerfile'  # Adjust path as needed

        return send_file(
            pdf_path,
            as_attachment=True,
            download_name='Dockerfile',  # Name for downloaded file
            mimetype='application/text'
        )
    except FileNotFoundError:
        return "Dockerfile file not found", 404

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = hash(password)
        
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        
        if existing_user:
            flash('Username or email already exists. Please choose another.', 'error')
            return render_template('register.html')
        
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and user.password == hash(password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
          pass

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if ('user_id' in session):
        username = session['username']
        if not (User.query.filter_by(username=username).first()):
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

    user_models = Model.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', models=user_models, username=username)


@app.route('/upload_model', methods=['POST'])
def upload_model():
    if ('user_id' in session):
        username = session['username']
        if not (User.query.filter_by(username=username).first()):
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

    if 'model_file' not in request.files:
        return redirect(url_for('dashboard'))

    file = request.files['model_file']

    if file.filename == '':
        return redirect(url_for('dashboard'))

    if file and allowed_file(file.filename):
        model_id = str(uuid.uuid4())
        filename = f"{model_id}.h5"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        try:
            file.save(file_path)

            new_model = Model(id=model_id, filename=filename, user_id=session['user_id'])
            db.session.add(new_model)
            db.session.commit()

        except Exception as e:
            if os.path.exists(file_path):
                os.remove(file_path)
    else:
       pass

    return redirect(url_for('dashboard'))

@app.route('/delete_model/<model_id>', methods=['GET'])
def delete_model(model_id):
    if ('user_id' in session):
        username = session['username']
        if not (User.query.filter_by(username=username).first()):
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))
 
    model = Model.query.filter_by(id=model_id, user_id=session['user_id']).first()

    if model:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], model.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(model)
        db.session.commit()
    else:
       pass

    return redirect(url_for('dashboard'))


@app.route('/run_model/<model_id>')
def run_model(model_id):
    if ('user_id' in session):
        username = session['username']
        if not (User.query.filter_by(username=username).first()):
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

    model_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{model_id}.h5')

    if not os.path.exists(model_path):
        return redirect(url_for('dashboard'))

    try:
        model = tf.keras.models.load_model(model_path)

        hours = np.arange(0, 24 * 7).reshape(-1, 1)
        predictions = model.predict(hours)

        days_of_week = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        daily_predictions = {f"{days_of_week[i // 24]} - Hour {i % 24}": round(predictions[i][0], 2) for i in range(len(predictions))}

        max_day = max(daily_predictions, key=daily_predictions.get)
        max_prediction = daily_predictions[max_day]

        model_summary = []
        model.summary(print_fn=lambda x: model_summary.append(x))
        model_summary = "\n".join(model_summary)

        return render_template(
            'run_model.html',
            model_summary=model_summary,
            daily_predictions=daily_predictions,
            max_day=max_day,
            max_prediction=max_prediction
        )
    except Exception as e:
        print(e)
        return redirect(url_for('dashboard'))



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1')

