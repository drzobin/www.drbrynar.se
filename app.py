from flask import Flask,session, request, flash, url_for, redirect, render_template, abort ,g
from flask.ext.login import login_user, logout_user , current_user , login_required
from models import Base, User, Picture, Logg
from flask.ext.login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from werkzeug import secure_filename
import hashlib, datetime, random, os

app = Flask(__name__)
app.config.from_pyfile("config.py")
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['UPLOAD_FOLDER'] = 'static/pictures/'
app.config['ALLOWED_EXTENSIONS'] = set(['tiff','jpeg','jpg','png','img','tif','gif','bmp'])

def allowed_file(filename):
  return '.' in filename and filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

@app.before_first_request
def setup():
  #Base.metadata.drop_all(bind=db.engine)
  #Base.metadata.create_all(bind=db.engine)
  pass

@app.before_request
def before_request():
    g.user = current_user

@login_manager.user_loader
def load_user(id):
  #return User.query.get(int(id))
  return db.session.query(User).get(int(id))

@app.route("/")
def start():
  if request.method == 'GET':
    print app.config["USER_PW_SALT"]
    db.session.add(Logg("GET start", request.remote_addr,request.user_agent.string))
    db.session.commit()
    rand = random.randrange(0, db.session.query(Picture).count()) 
    pic_row = db.session.query(Picture)[rand]
    pic_filename = url_for('static', filename ="pictures/" + pic_row.filename)
    return render_template('start.html', pic_url = pic_filename)

@app.route("/upload", methods=['POST', 'GET'])
@app.route("/u", methods=['POST', 'GET'])
@login_required
def upload():
  if request.method == 'GET':
    db.session.add(Logg("GET upload", request.remote_addr,request.user_agent.string))
    db.session.commit()
    return render_template('upload.html')
  if request.method == 'POST':
    db.session.add(Logg("POST upload", request.remote_addr,request.user_agent.string))
    db.session.commit()
    file = request.files['file']
    if file and allowed_file(file.filename):
      filename = secure_filename(file.filename)
      db.session.add(Picture(2, filename, request.remote_addr,request.user_agent.string))
      db.session.commit()
      file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
      db.session.add(Logg("POST upload file: " + filename, request.remote_addr,request.user_agent.string))
      db.session.commit()
      return render_template('start.html')
    return redirect(url_for('upload'))

@app.route("/login", methods=['POST', 'GET'])
@app.route("/l", methods=['POST', 'GET'])
def login():
  if request.method == 'GET':
    db.session.add(Logg("GET login", request.remote_addr,request.user_agent.string))
    db.session.commit()
    return render_template('login.html')
  if request.method == 'POST':
    db.session.add(Logg("POST login", request.remote_addr,request.user_agent.string))
    db.session.commit()
    if request.form["email"] and request.form["password"]:
      hashed_password = hashlib.sha512(request.form["password"] + app.config["USER_PW_SALT"]).hexdigest()
      users = db.session.query(User).filter(User.email == request.form["email"], User.password == hashed_password).first()
      if users is None:
        db.session.add(Logg("POST login failed login with email: " + request.form["email"] + " password: " + request.form["password"], request.remote_addr,request.user_agent.string))
        db.session.commit()
        return render_template('error.html', error_message = "Username or/and password is invalid")
      login_user(users)
      db.session.add(Logg("POST login succesfully login with email: " + request.form["email"] + " password: " + request.form["password"], request.remote_addr,request.user_agent.string))
      db.session.commit()
      return redirect(url_for("start"))
    else:
      db.session.add(Logg("POST login empty form", request.remote_addr,request.user_agent.string))
      db.session.commit()
      return render_template('error.html', error_message = "Empty form")

@app.route("/logout", methods=['GET'])
def logout():
  db.session.add(Logg("GET logout", request.remote_addr,request.user_agent.string))
  db.session.commit()
  logout_user()
  return redirect(url_for("start"))
  
@app.route("/register/", methods=['POST', 'GET'])
@app.route("/r/", methods=['POST', 'GET'])
def register():
  if request.method == 'GET':
    db.session.add(Logg("GET register", request.remote_addr,request.user_agent.string))
    db.session.commit()
    return render_template('register.html')
  if request.method == 'POST':
    db.session.add(Logg("POST register", request.remote_addr,request.user_agent.string))
    db.session.commit()
    if not request.form["email"] or not request.form["password1"] or not request.form["password2"]:
      db.session.add(Logg("POST registeri empty form", request.remote_addr,request.user_agent.string))
      db.session.commit()
      return render_template('error.html', error_message = "Empty form")
    if request.form["password1"] == request.form["password2"]:
      hashed_password = hashlib.sha512(request.form["password1"] + app.config["USER_PW_SALT"]).hexdigest()
      db.session.add(User(request.form["email"], hashed_password))
      db.session.commit()
      db.session.add(Logg("POST register sussesfully register email: " + request.form["email"]  + " password: " + request.form["password1"], request.remote_addr,request.user_agent.string))
      db.session.commit()
      return redirect(url_for("login"))
    else:
      db.session.add(Logg("POST register error password do not match password1: " + request.form["password1"]  + " password2: " + request.form["password2"], request.remote_addr,request.user_agent.string))
      db.session.commit()
      return render_template('error.html', error_message = "Passwords do not match")

if __name__ == "__main__":
  app.debug = True
  app.run(host='0.0.0.0')
