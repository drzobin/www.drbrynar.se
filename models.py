from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
import datetime, time

Base = declarative_base()

class User(Base):
  __tablename__ = 'users'

  id = Column(Integer, unique=True, primary_key=True, autoincrement=True)
  username = Column(String())
  email = Column(String())
  password = Column(String())
  registered_on = Column(DateTime())

  def __init__(self, username, email, password):
    self.username = username
    self.email = email
    self.password = password
    self.registered_on = time.strftime('%Y-%m-%d %H:%M:%S')

  def is_authenticated(self):
    return True
 
  def is_active(self):
    return True
 
  def is_anonymous(self):
    return False
 
  def get_id(self):
    return unicode(self.id)

  def __repr__(self):
    return '<User %r>' % self.username

class Picture(Base):
  __tablename__ = 'pictures'

  id = Column(Integer, unique=True, primary_key=True, autoincrement=True)
  user_id = Column(Integer())
  filename = Column(String())
  description = Column(String())
  md5 = Column(String())
  sha1 = Column(String())
  sha256 = Column(String())
  uploader_ip = Column(String())
  uploader_useragent = Column(String())
  uploaded_on = Column(DateTime())

  def __init__(self, user_id, filename,description,md5,sha1,sha256,uploader_ip, uploader_useragent):
    self.user_id = user_id
    self.filename = filename
    self.description = description
    self.md5 = md5
    self.sha2 = sha1
    self.sha256 = sha256
    self.uploader_ip = uploader_ip
    self.uploader_useragent = uploader_useragent
    self.uploaded_on = time.strftime('%Y-%m-%d %H:%M:%S')

  def id_as_str(self):
    return str(self.id)

class Logg(Base):
  __tablename__ = 'loggs'

  id = Column(Integer, unique=True, primary_key=True, autoincrement=True)
  action = Column(String())
  ip = Column(String())
  useragent = Column(String())
  action_time = Column(DateTime())

  def __init__(self, action, ip, useragent):
    self.action = action
    self.ip = ip
    self.useragent = useragent
    self.action_time = time.strftime('%Y-%m-%d %H:%M:%S')
