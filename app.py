from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config.from_pyfile("config.py")
db = SQLAlchemy(app)

@app.route("/")
def hello():
  return "test"

if __name__ == "__main__":
  app.run(host='0.0.0.0')
