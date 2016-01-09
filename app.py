from flask import Flask,session, request, flash, url_for, redirect, render_template, abort ,g
from flask.ext.login import login_user, logout_user , current_user , login_required
from models import Base, User, Picture, Logg
from flask.ext.login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from werkzeug import secure_filename
from flask_recaptcha import ReCaptcha
from flask.ext.images import Images
from email.mime.text import MIMEText
import hashlib, datetime, random, os, smtplib, string, imghdr, shutil

app = Flask(__name__)
app.config.from_pyfile("config.py")
db = SQLAlchemy(app)
recaptcha = ReCaptcha(app=app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

images = Images(app)

#temp folder to save files befor moved to upload folder
app.config['TMP_FOLDER'] = '/opt/www.drbrynar.se/tmp/'

#folder to save uploaded files to
app.config['UPLOAD_FOLDER'] = '/opt/www.drbrynar.se/static/pictures/'

#allowed file exstenstion when uploading a file
app.config['ALLOWED_EXTENSIONS'] = set(['tiff','jpeg','jpg','png','gif','bmp'])

#max size of the uploaded files
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024

def allowed_file(filename):
  return '.' in filename and filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

def sendPasswordByEmail(toEmail,username,password):
  mailSubject = "Login details on www.drbrynar.se"
  mailText = "Username: " + username + "\n" + "Password: " + password + "\n\n" + "Kind regards" + "\n" + "DrBrynar" 
  msg = MIMEText(mailText)

  msg["Subject"] = mailSubject
  msg["From"] = "no-reply@www.drbrynar.se"
  msg["To"] = toEmail

  s = smtplib.SMTP('localhost')
  s.sendmail(msg["From"], msg["To"], msg.as_string())
  s.quit()

def genID(size=32):
  chars=string.ascii_uppercase + string.digits
  return ''.join(random.choice(chars) for _ in range(size))


def generatePassword(length):
  chars = string.ascii_letters + string.digits + '!@#$%&*()/[]=?'
  random.seed = (os.urandom(1024))

  return ''.join(random.choice(chars) for i in range(length))

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
    #logg to db
    db.session.add(Logg("GET /", request.remote_addr,request.user_agent.string))
    db.session.commit()

    #if there has not been any picture upload show error
    if db.session.query(Picture).count() == 0:
      return render_template('error.html', error_message = "No pictures is uploaded :(")
    #show random picture to user
    else:
      rand = random.randrange(0, db.session.query(Picture).count()) 
      pic_row = db.session.query(Picture)[rand]

      return render_template('start.html', pic = pic_row)

@app.route("/show_all_pics")
def show_all_pics():
  if request.method == 'GET':
    #logg to db
    db.session.add(Logg("GET /show_all_pics", request.remote_addr,request.user_agent.string))
    db.session.commit()

    pics = db.session.query(Picture).all()

    return render_template('show_all_pics.html',pics = pics)


@app.route("/upload", methods=['POST', 'GET'])
@app.route("/u", methods=['POST', 'GET'])
@login_required
def upload():
  if request.method == 'GET':
    #logg to db
    db.session.add(Logg("GET /upload", request.remote_addr,request.user_agent.string))
    db.session.commit()

    return render_template('upload.html')

  if request.method == 'POST':
    #logg to db
    db.session.add(Logg("POST /upload", request.remote_addr,request.user_agent.string))
    db.session.commit()

    #get file
    file = request.files['file']

    if file:
      #if file exstienstion is not allowed logg and show error
      if not allowed_file(file.filename):
        #logg to db
        db.session.add(Logg("POST /upload: files exstenstion is not allowed", request.remote_addr,request.user_agent.string))
        db.session.commit()

        return render_template('error.html', error_message = "File is not of allowed type. Allowed files are: " + str(app.config['ALLOWED_EXTENSIONS']))

      #create secure filename
      filename = secure_filename(file.filename)

      #save file in tmp folder
      tmpID = genID()
      tmpFolder = app.config['TMP_FOLDER'] + tmpID + "/" 
      os.mkdir(tmpFolder)
      file.save(os.path.join(tmpFolder, filename))

      #get checksums of file
      file_in_mem = open(tmpFolder + filename,"rb").read()
      md5 = hashlib.md5(file_in_mem).hexdigest()
      sha1 = hashlib.sha1(file_in_mem).hexdigest()
      sha256 = hashlib.sha256(file_in_mem).hexdigest()

      #check that file is a picture, if file is not a picture do not move file to upload folder
      fileType = imghdr.what(tmpFolder + filename)
      if not fileType in app.config['ALLOWED_EXTENSIONS']:
        #logg to db
        db.session.add(Logg("POST /upload: uploaded file can not be validated with imghdr", request.remote_addr,request.user_agent.string))
        db.session.commit()

        return render_template('error.html', error_message = "File is not of allowed type. Allowed files are: " + str(app.config['ALLOWED_EXTENSIONS']))

      if request.form["description"]:
        description = request.form["description"]
      else:
        description = "none"

      #add file data to db
      picture = Picture(current_user.get_id(), filename, description, md5, sha1, sha256, request.remote_addr, request.user_agent.string)
      db.session.add(picture)
      db.session.commit()

      #get id from db
      newFilename = str(picture.id)

      #move file to upload folder
      shutil.move(tmpFolder + filename, app.config['UPLOAD_FOLDER'] + newFilename)

      #remove tmp folder
      shutil.rmtree(tmpFolder)

      #logg to db
      db.session.add(Logg("POST /upload: filename " + filename + " has been uploaded", request.remote_addr,request.user_agent.string))
      db.session.commit()

      #return render_template('start.html')
      return redirect(url_for('start'))

    #if any of the form is empty logg and show error
    else:
      #logg to db
      db.session.add(Logg("POST /upload: empty form", request.remote_addr,request.user_agent.string))
      db.session.commit()

      return render_template('error.html', error_message = "Empty form")

@app.route("/login", methods=['POST', 'GET'])
@app.route("/l", methods=['POST', 'GET'])
def login():
  if request.method == 'GET':
    #logg to db
    db.session.add(Logg("GET /login", request.remote_addr,request.user_agent.string))
    db.session.commit()

    return render_template('login.html')

  if request.method == 'POST':
    #logg to db
    db.session.add(Logg("POST /login", request.remote_addr,request.user_agent.string))
    db.session.commit()

    if request.form["username"] and request.form["password"]:
      hashed_password = hashlib.sha512(request.form["password"] + app.config["USER_PW_SALT"]).hexdigest()
      user = db.session.query(User).filter(User.username == request.form["username"], User.password == hashed_password).first()

      #if login files logg and show error
      if user is None:
        #logg to db
        db.session.add(Logg("POST /login: failed login with username: " + request.form["username"] + " password: " + request.form["password"], request.remote_addr,request.user_agent.string))
        db.session.commit()

        return render_template('error.html', error_message = "Username or/and password is invalid")

      #if login success logg and login user
      else:
        #logg to db
        db.session.add(Logg("POST /login: succesfully login with username: " + request.form["username"], request.remote_addr,request.user_agent.string))
        db.session.commit()

        login_user(user)

        return redirect(url_for("start"))

    #if any of the form is empty logg and show errot
    else:
      #logg to db
      db.session.add(Logg("POST /login: empty form", request.remote_addr,request.user_agent.string))
      db.session.commit()

      return render_template('error.html', error_message = "Empty form")

@app.route("/logout", methods=['GET'])
def logout():
  #logg to db
  db.session.add(Logg("GET /logout", request.remote_addr,request.user_agent.string))
  db.session.commit()

  logout_user()

  return redirect(url_for("start"))
  
@app.route("/register/", methods=['POST', 'GET'])
@app.route("/r/", methods=['POST', 'GET'])
def register():
  if request.method == 'GET':
    #logg to db
    db.session.add(Logg("GET /register", request.remote_addr,request.user_agent.string))
    db.session.commit()

    return render_template('register.html')

  if request.method == 'POST':
    #logg to db
    db.session.add(Logg("POST /register", request.remote_addr,request.user_agent.string))
    db.session.commit()

    #if recaptcha fileas logg and show error
    if not recaptcha.verify():
      #logg to db
      db.session.add(Logg("POST /registeri: recaptcha failed", request.remote_addr,request.user_agent.string))
      db.session.commit()

      return render_template('error.html', error_message = "You are not a human")

    if request.form["email"] and request.form["username"]:
      #check that username is not used before
      if db.session.query(User).filter(User.username == request.form["username"]).count() != 0:
        #logg to db
        db.session.add(Logg("POST /register: username is used before", request.remote_addr,request.user_agent.string))
        db.session.commit()

        return render_template('error.html', error_message = "Choose another username")

      #check that email is not used before
      if db.session.query(User).filter(User.email == request.form["email"]).count() != 0:
        #logg to db
        db.session.add(Logg("POST /register: email is used before", request.remote_addr,request.user_agent.string))
        db.session.commit()

        return render_template('error.html', error_message = "Choose another email")

      #generate password and send it to users email
      password = generatePassword(12)
      hashed_password = hashlib.sha512(password + app.config["USER_PW_SALT"]).hexdigest()
      db.session.add(User(request.form["username"],request.form["email"], hashed_password))
      db.session.commit()
      sendPasswordByEmail(request.form["email"],request.form["username"],password)

      return redirect(url_for("login"))

    #if form is empty logg and show error
    else:
      #logg to db
      db.session.add(Logg("POST /register: empty form", request.remote_addr,request.user_agent.string))
      db.session.commit()

      return render_template('error.html', error_message = "Passwords do not match")

if __name__ == "__main__":
  app.debug = True
  #app.debug = False
  app.run(host='0.0.0.0',port=80)
