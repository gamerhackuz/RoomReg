from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import jwt, io, qrcode, base64, secrets

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///registration.db'
app.config['SECRET_KEY'] = secrets.token_hex(32)
db = SQLAlchemy(app)

# 🧱 Modellar
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    registrations = db.relationship('Registration', backref='room', lazy=True)

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    ticket_code = db.Column(db.String(36), unique=True, nullable=False)
    checked_in = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()

# 🔐 Yordamchi funksiyalar
def generate_token(user_id):
    return jwt.encode({'uid': user_id, 'exp': datetime.utcnow() + 900}, app.config['SECRET_KEY'])

def decode_token(token):
    try: return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except: return None

# 🌐 API Endpointlar
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username band'}), 400
    u = User(username=data['username'], password_hash=data['password']) # Production: werkzeug.security
    db.session.add(u); db.session.commit()
    return jsonify({'token': generate_token(u.id)})

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    u = User.query.filter_by(username=data['username'], password_hash=data['password']).first()
    return jsonify({'token': generate_token(u.id)}) if u else (jsonify({'error': 'Xato'}), 401)

@app.route('/rooms', methods=['POST'])
def create_room():
    token = request.headers.get('Authorization','').split()[-1]
    if not decode_token(token): return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    r = Room(name=data['name'], capacity=data['capacity'], 
             start_time=datetime.fromisoformat(data['start']), 
             end_time=datetime.fromisoformat(data['end']))
    db.session.add(r); db.session.commit()
    return jsonify({'room_id': r.id}), 201

@app.route('/rooms/<int:room_id>/register', methods=['POST'])
def register_room(room_id):
    token = request.headers.get('Authorization','').split()[-1]
    payload = decode_token(token)
    if not payload: return jsonify({'error': 'Unauthorized'}), 401
    
    room = Room.query.get_or_404(room_id)
    # Sig'im tekshiruvi
    if len(room.registrations) >= room.capacity:
        return jsonify({'error': 'Xona to\'lgan'}), 409
    # Vaqt to'qnashuvi tekshiruvi
    start, end = room.start_time, room.end_time
    conflict = Registration.query.join(Room).filter(
        Registration.user_id == payload['uid'],
        Room.start_time < end, Room.end_time > start
    ).first()
    if conflict:
        return jsonify({'error': 'Sizda shu vaqtda boshqa xona bor'}), 409

    ticket = secrets.token_hex(8)
    reg = Registration(user_id=payload['uid'], room_id=room_id, ticket_code=ticket)
    db.session.add(reg); db.session.commit()
    return jsonify({'ticket': ticket, 'room': room.name, 'time': f"{start} - {end}"})

@app.route('/ticket/<ticket_code>/qr', methods=['GET'])
def get_qr(ticket_code):
    reg = Registration.query.filter_by(ticket_code=ticket_code).first_or_404()
    qr = qrcode.make(f"TICKET:{ticket_code}|USER:{reg.user_id}|ROOM:{reg.room_id}")
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/checkin', methods=['POST'])
def checkin():
    data = request.get_json()
    reg = Registration.query.filter_by(ticket_code=data['ticket']).first()
    if not reg: return jsonify({'error': 'Noto\'g\'ri bilet'}), 404
    if reg.checked_in: return jsonify({'error': 'Allaqachon kirgan'}), 400
    reg.checked_in = True; db.session.commit()
    return jsonify({'message': 'Muvaffaqiyatli kirdingiz!', 'user_id': reg.user_id})

if __name__ == '__main__':
    app.run(port=5000, debug=True)
