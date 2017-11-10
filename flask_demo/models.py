from db import db
from flask_login import UserMixin


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)

    ukey = db.Column(db.String(20), unique=True, nullable=False)
    credential_id = db.Column(db.String(250), unique=True, nullable=False)
    display_name = db.Column(db.String(160), unique=False, nullable=False)
    pub_key = db.Column(db.String(65), unique=True, nullable=True)
    sign_count = db.Column(db.Integer, default=0)
    username = db.Column(db.String(80), unique=True, nullable=False)
    rp_id = db.Column(db.String(253), nullable=False)
    icon_url = db.Column(db.String(2083), nullable=False)

    def __repr__(self):
        return '<User %r %r>' % (self.display_name, self.username)
