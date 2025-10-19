from flask import Flask
from pymongo import MongoClient
from config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    return app

def get_db(app):
    client = MongoClient(app.config['MONGO_URI'])
    return client.get_database()
