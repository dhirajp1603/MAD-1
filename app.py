from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///FreeHands.db'
app.config['SECRET_KEY'] = "FreeHands"

db = SQLAlchemy(app)

from models import *
from routes import *


if __name__ == '__main__':
    app.run(debug=True)