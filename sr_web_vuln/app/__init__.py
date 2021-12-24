from os.path import dirname, join, realpath

from config import Config
from flask import Flask
from flask_cors import CORS
from flask_login import LoginManager
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate, migrate
from flask_sqlalchemy import SQLAlchemy

UPLOADS_PATH = join(dirname(realpath(__file__)), 'static/uploads/')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOADS_PATH
app.config.from_object(Config)
# cors = CORS(app, resources={r"/api/*": {"origins": "localhost"}})
# cors = CORS(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'

from app import errors, models, routes
