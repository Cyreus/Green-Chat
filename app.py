import os
import uuid
from datetime import datetime
from flask import *
from flask_socketio import SocketIO
from flask_migrate import Migrate
from models import db, Users, Chat, Messages
from flask_mail import Mail, Message
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///'
app.config['SECRET_KEY'] = 'default_secret_key'
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = None
app.config['MAIL_PASSWORD'] = None
app.config['DEFAULT_PHOTO_URL'] = 'default_photo_url'

config_file_location = "/home/cyreus/PycharmProjects/new-turing/config/dev.cfg"

if config_file_location:
    app.config.from_pyfile(config_file_location, silent=False)
else:
    # Load configurations in order: dev, prp, prod
    app.config.from_pyfile('config/dev.cfg', silent=True)
    app.config.from_pyfile('config/prp.cfg', silent=True)
    app.config.from_pyfile('config/prod.cfg', silent=False)

socketio = SocketIO(app)

db.init_app(app)
migrate = Migrate(app, db)
mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = Users.query.filter_by(email=email).first()

        if user:
            token = os.urandom(24).hex()
            user.reset_token = token
            db.session.commit()

            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request',
                          sender='ali@demomailtrap.com',
                          recipients=[email])
            msg.body = f'Please click the link to reset your password: {reset_link}'
            mail.send(msg)

            flash('A password reset link has been sent to your email.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email address not found', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = Users.query.filter_by(reset_token=token).first()

    if not user:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = generate_password_hash(request.form['password'])
        user.password = new_password
        user.reset_token = None
        db.session.commit()

        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route('/main')
@login_required
def index():
    username = current_user.username
    id_user = current_user.id
    url = current_user.profile_photo_url
    users = Users.query.filter(Users.id != id_user).all()
    return render_template('index.html', users=users, username=username, id=id_user, url=url)


@app.route('/user_register')
def user_register():
    return render_template('user_register.html')


@app.route('/add_user', methods=['POST'])
def add_user():
    try:
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        email = request.form['email'].strip()
        profile = request.form['profile'].strip()

        if not username or not password or not email:
            flash('All fields are required.', 'danger')
            return redirect(url_for('user_register'))

        if Users.query.filter_by(email=email).first():
            flash('Email address already exists.', 'danger')
            return redirect(url_for('user_register'))

        if not profile:
            profile = app.config['DEFAULT_PHOTO_URL']

        hashed_password = generate_password_hash(password)
        new_user = Users(username=username, password=hashed_password, email=email, profile_photo_url=profile)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    except Exception as e:
        db.session.rollback()
        flash('An error occurred during registration. Please try again.', 'danger')
        print(e)
        return redirect(url_for('user_register'))


@app.route('/send_photo', methods=['POST'])
@login_required
def send_photo():
    if 'photo' not in request.files:
        return jsonify({'success': False})

    photo = request.files['photo']
    if photo:
        photo_filename = f"{uuid.uuid4()}.png"
        photo.save(os.path.join('static/photos', photo_filename))
        photo_url = f"/static/photos/{photo_filename}"
        return jsonify({'success': True, 'photo_url': photo_url})

    return jsonify({'success': False})


@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    user_id = current_user.id
    user = Users.query.get(user_id)

    if request.method == 'POST':
        new_username = request.form['username']
        new_email = request.form['email']
        new_password = request.form['password']
        profile_photo = request.files['profile_photo']
        user.username = new_username
        user.email = new_email
        if new_password:
            user.password = new_password
        if profile_photo:
            photo_filename = f"{uuid.uuid4()}.png"
            profile_photo.save(os.path.join('static/profile_photos', photo_filename))
            user.profile_photo_url = f"/static/profile_photos/{photo_filename}"

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('update_profile.html', user=user)


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = Users.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

    return render_template('user_login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/chat/<chat_key>')
def get_chat_messages(chat_key):
    page = request.args.get('page', 1, type=int)
    per_page = 10
    chat = Chat.query.filter_by(chat_key=chat_key).first()
    if not chat:
        return jsonify({'messages': [], 'has_next': False})

    messages = Messages.query.filter_by(chat_id=chat_key).paginate(page=page, per_page=per_page, error_out=False)
    message_list = []
    message_list.clear()
    for msg in messages.items:
        sender = Users.query.get(msg.sender_id)
        message_list.append({
            'username_sender': sender.username,
            'text': msg.message,
            'id_sender': msg.sender_id,
            'sender_photo': Users.query.get(msg.sender_id).profile_photo_url,
            'receiver_photo': Users.query.get(msg.receiver_id).profile_photo_url,
            'inserted_date': msg.inserted_date.strftime('%d-%m-%Y %H:%M'),
        })
    return jsonify({'messages': message_list, 'has_next': messages.has_next})


@app.route('/get_chat_key/<sender_id>/<receiver_id>', methods=['GET'])
@login_required
def get_chat_key(sender_id, receiver_id):
    chats = Chat.query.filter(
        Chat.users.contains([sender_id, receiver_id])
    ).all()

    if chats:
        chat_key = chats[0].chat_key
    else:
        chat_key = "chat"

    return jsonify({'chat_key': chat_key})


def add_db(msg):
    sender_id = msg.get('sender_id')
    receiver_id = msg.get('receiver_id')
    text = msg.get('text')

    if not sender_id or not receiver_id or not text:
        print("Error: Missing sender_id, receiver_id, or text in message.")
        return

    key = uuid.uuid4().hex

    chats = Chat.query.filter(
        Chat.users.contains([sender_id, receiver_id])
    ).all()

    if not chats:
        chat = Chat(users=[sender_id, receiver_id], chat_key=key)
        db.session.add(chat)
        db.session.commit()
        chat_key = chat.chat_key
    else:
        chat_key = chats[0].chat_key

    new_message = Messages(
        sender_id=sender_id,
        receiver_id=receiver_id,
        message=text,
        chat_id=chat_key
    )
    db.session.add(new_message)
    db.session.commit()

    print("Message and chat successfully added to the database.")


@socketio.on('message')
def handle_message(msg):
    print(f"Message from {msg['user']}: {msg['text']}")
    add_db(msg)

    sender = Users.query.get(msg['sender_id'])
    receiver = Users.query.get(msg['receiver_id'])

    msg['sender_photo'] = sender.profile_photo_url
    msg['receiver_photo'] = receiver.profile_photo_url
    msg['inserted_date'] = datetime.now().strftime('%d-%m-%Y %H:%M')

    socketio.emit('message', msg)


@socketio.on('typing')
def handle_typing(msg):
    print(f"{msg['user']} is typing...")
    socketio.emit('typing', msg['user'])


@socketio.on('stop typing')
def handle_stop_typing(msg):
    print(f"{msg['user']} stopped typing.")
    socketio.emit('stop typing', msg['user'])


if __name__ == '__main__':
    socketio.run(app, debug=True, use_reloader=True, log_output=True)
