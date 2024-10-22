from dotenv import load_dotenv

load_dotenv()

SECRET_KEY="dhirajp"
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_DATABASE_URI = 'sqlite:///sqlite3.db'
