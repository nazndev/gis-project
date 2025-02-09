from flask import Flask
from flask_jwt_extended import JWTManager
from app.routes import geostat_bp
from app.database import db, init_db
import os


def create_app():
    app = Flask(__name__)
    app.config.from_object("app.config.Config")

    init_db(app)
    jwt = JWTManager(app)

    app.register_blueprint(geostat_bp, url_prefix='/api/geostat')

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0', port=5002, debug=True)