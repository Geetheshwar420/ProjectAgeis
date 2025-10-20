from flask import Flask
from pymongo import MongoClient
from config import Config
import logging

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    return app

def get_db(app):
    mongo_uri = app.config['MONGO_URI']
    # Set a short timeout so failures surface quickly on deployed environments
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=3000)
    try:
        # Force connection on a request as the
        # connect=True parameter of MongoClient seems
        # to be useless here
        client.admin.command('ping')
        logging.info('MongoDB ping successful')
    except Exception as e:
        logging.error(f'MongoDB connection failed: {e}. URI host may be unreachable or IP not allowlisted.')
        # Still return the client; individual calls may retry once infra is corrected
    return client.get_database()
