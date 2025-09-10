from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, FileField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import datetime
from flask_sqlalchemy import SQLAlchemy
import os


app = Flask(__name__)
csrf = CSRFProtect(app)

# Ensure csrf_token is available in all templates
@app.context_processor
def inject_csrf_token():
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=generate_csrf())

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///classsite.db'
app.config['SECRET_KEY'] = 'your_secret_key'

app.config['UPLOAD_FOLDER'] = 'static'
db = SQLAlchemy(app)




class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    profile_pic = db.Column(db.String(120))
    role = db.Column(db.String(50))
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_teacher = db.Column(db.Boolean, default=False)
    activity_log = db.Column(db.Text)
    badge = db.Column(db.String(50))
    followers = db.relationship('Follow', foreign_keys='Follow.followed_id', backref='followed', lazy='dynamic')
    following = db.relationship('Follow', foreign_keys='Follow.follower_id', backref='follower', lazy='dynamic')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic')
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    messages_received = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy='dynamic')
    reposts = db.relationship('Repost', backref='user', lazy='dynamic')
    avatar = db.Column(db.String(120))



class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(120))
    date = db.Column(db.String(20))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tags = db.Column(db.String(120))
    likes = db.relationship('Like', backref='post', lazy='dynamic')
    comments = db.relationship('Comment', backref='post', lazy='dynamic')
    reposts = db.relationship('Repost', backref='post', lazy='dynamic')
    trending_score = db.Column(db.Integer, default=0)
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(20))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'))
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy='dynamic')
    mentions = db.Column(db.String(120))

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'))
    reaction = db.Column(db.String(20), default='like')

class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.String(20))

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(200))
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.String(20))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.String(20))

class Repost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'))
    timestamp = db.Column(db.String(20))


# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        role = request.form['role']
        password = request.form['password']
        email = request.form['email']
        profile_pic_file = request.files.get('profile_pic')
        profile_pic_filename = None
        if profile_pic_file and profile_pic_file.filename:
            profile_pic_filename = secure_filename(profile_pic_file.filename)
            profile_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_pic_filename)
            profile_pic_file.save(profile_pic_path)
        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('register'))
        password_hash = generate_password_hash(password)
        user = User(first_name=first_name, profile_pic=profile_pic_filename, role=role, password_hash=password_hash, email=email)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['is_teacher'] = user.is_teacher
            flash('Logged in successfully!')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.')
    return redirect(url_for('index'))


# Home page with search, filter, sort, pagination, recent posts sidebar
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    user_filter = request.args.get('user', None, type=int)
    role_filter = request.args.get('role', None)
    tag_filter = request.args.get('tag', None)
    sort = request.args.get('sort', 'date')
    query = BlogPost.query
    if search:
        query = query.filter(BlogPost.title.contains(search) | BlogPost.content.contains(search))
    if user_filter:
        query = query.filter_by(user_id=user_filter)
    if role_filter:
        query = query.join(User).filter(User.role == role_filter)
    if tag_filter:
        query = query.filter(BlogPost.tags.contains(tag_filter))
    if sort == 'title':
        query = query.order_by(BlogPost.title)
    else:
        query = query.order_by(BlogPost.id.desc())
    posts = query.paginate(page=page, per_page=5)
    recent_posts = BlogPost.query.order_by(BlogPost.id.desc()).limit(5).all()
    return render_template('index.html', posts=posts, recent_posts=recent_posts)


# Bios page
@app.route('/bios')
def bios():
    users = User.query.all()
    return render_template('bios.html', users=users)


# User profile page with follow/unfollow and activity feed
@app.route('/profile/<int:user_id>', methods=['GET', 'POST'])
def profile(user_id):
    user = User.query.get_or_404(user_id)
    current_user = User.query.get(session.get('user_id')) if session.get('user_id') else None
    is_following = False
    if current_user:
        is_following = Follow.query.filter_by(follower_id=current_user.id, followed_id=user.id).first() is not None
        if request.method == 'POST':
            if 'follow' in request.form:
                if not is_following and current_user.id != user.id:
                    follow = Follow(follower_id=current_user.id, followed_id=user.id, timestamp=datetime.datetime.now().strftime('%Y-%m-%d'))
                    db.session.add(follow)
                    db.session.add(Notification(user_id=user.id, message=f'{current_user.first_name} followed you!', timestamp=datetime.datetime.now().strftime('%Y-%m-%d')))
                    db.session.commit()
            elif 'unfollow' in request.form:
                f = Follow.query.filter_by(follower_id=current_user.id, followed_id=user.id).first()
                if f:
                    db.session.delete(f)
                    db.session.commit()
    followers_count = Follow.query.filter_by(followed_id=user.id).count()
    following_count = Follow.query.filter_by(follower_id=user.id).count()
    activity = BlogPost.query.filter_by(user_id=user.id).order_by(BlogPost.id.desc()).limit(10).all()
    badges = user.badge.split(',') if user.badge else []
    return render_template('profile.html', user=user, current_user=current_user, is_following=is_following, followers_count=followers_count, following_count=following_count, activity=activity, badges=badges)

# Followed users feed (activity feed)
@app.route('/feed')
def feed():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to view your feed.')
        return redirect(url_for('login'))
    following = Follow.query.filter_by(follower_id=user_id).all()
    following_ids = [f.followed_id for f in following]
    posts = BlogPost.query.filter(BlogPost.user_id.in_(following_ids)).order_by(BlogPost.id.desc()).limit(20).all()
    reposts = Repost.query.filter(Repost.user_id.in_(following_ids)).order_by(Repost.id.desc()).limit(20).all()
    return render_template('feed.html', posts=posts, reposts=reposts)

# Notifications page
@app.route('/notifications')
def notifications():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to view notifications.')
        return redirect(url_for('login'))
    notes = Notification.query.filter_by(user_id=user_id).order_by(Notification.id.desc()).limit(50).all()
    for note in notes:
        note.is_read = True
    db.session.commit()
    return render_template('notifications.html', notifications=notes)

# Direct messaging
@app.route('/messages', methods=['GET', 'POST'])
def messages():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to view messages.')
        return redirect(url_for('login'))
    current_user = User.query.get(user_id)
    users = User.query.filter(User.id != user_id).all()
    selected_id = request.args.get('user', type=int)
    selected_user = User.query.get(selected_id) if selected_id else None
    chat = []
    if selected_user:
        chat = Message.query.filter(
            ((Message.sender_id == user_id) & (Message.receiver_id == selected_user.id)) |
            ((Message.sender_id == selected_user.id) & (Message.receiver_id == user_id))
        ).order_by(Message.id).all()
    if request.method == 'POST' and selected_user:
        content = request.form['content']
        msg = Message(sender_id=user_id, receiver_id=selected_user.id, content=content, timestamp=datetime.datetime.now().strftime('%Y-%m-%d %H:%M'))
        db.session.add(msg)
        db.session.add(Notification(user_id=selected_user.id, message=f'New message from {current_user.first_name}', timestamp=datetime.datetime.now().strftime('%Y-%m-%d')))
        db.session.commit()
        chat.append(msg)
    return render_template('messages.html', users=users, selected_user=selected_user, chat=chat)

# Repost a post
@app.route('/repost/<int:post_id>', methods=['POST'])
def repost(post_id):
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to repost.')
        return redirect(url_for('login'))
    post = BlogPost.query.get_or_404(post_id)
    repost = Repost(user_id=user_id, post_id=post.id, timestamp=datetime.datetime.now().strftime('%Y-%m-%d'))
    db.session.add(repost)
    db.session.add(Notification(user_id=post.user_id, message=f'Your post was reposted!', timestamp=datetime.datetime.now().strftime('%Y-%m-%d')))
    db.session.commit()
    flash('Post reposted!')
    return redirect(url_for('feed'))

# Add reaction to post
@app.route('/react/<int:post_id>', methods=['POST'])
def react(post_id):
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to react.')
        return redirect(url_for('login'))
    reaction = request.form.get('reaction', 'like')
    like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()
    if like:
        like.reaction = reaction
    else:
        like = Like(user_id=user_id, post_id=post_id, reaction=reaction)
        db.session.add(like)
    db.session.add(Notification(user_id=BlogPost.query.get(post_id).user_id, message=f'Your post got a {reaction}!', timestamp=datetime.datetime.now().strftime('%Y-%m-%d')))
    db.session.commit()
    flash(f'Reacted with {reaction}!')
    return redirect(url_for('view_post', post_id=post_id))

# Mention user in comment
def handle_mentions(content, post_id, user_id):
    import re
    mentioned = re.findall(r'@([A-Za-z0-9_]+)', content)
    for username in mentioned:
        user = User.query.filter_by(first_name=username).first()
        if user:
            db.session.add(Notification(user_id=user.id, message=f'You were mentioned in a post!', timestamp=datetime.datetime.now().strftime('%Y-%m-%d')))
    db.session.commit()
    return ','.join(mentioned)

# Trending tags and posts
@app.route('/trending')
def trending():
    trending_posts = BlogPost.query.order_by(BlogPost.trending_score.desc()).limit(10).all()
    trending_tags = db.session.query(BlogPost.tags).group_by(BlogPost.tags).order_by(db.func.count(BlogPost.tags).desc()).limit(10).all()
    return render_template('trending.html', posts=trending_posts, tags=[t[0] for t in trending_tags])

# Award badge (admin only)
@app.route('/award_badge/<int:user_id>', methods=['POST'])
def award_badge(user_id):
    if not session.get('is_teacher'):
        flash('Only teachers can award badges.')
        return redirect(url_for('profile', user_id=user_id))
    user = User.query.get_or_404(user_id)
    badge = request.form['badge']
    if user.badge:
        user.badge += ',' + badge
    else:
        user.badge = badge
    db.session.commit()
    flash('Badge awarded!')
    return redirect(url_for('profile', user_id=user_id))

# Create blog post (all users)
@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if not session.get('user_id'):
        flash('You must be logged in to create a post.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        tags = request.form.get('tags', '')
        image_file = request.files.get('image')
        image_filename = None
        if image_file and image_file.filename:
            image_filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image_file.save(image_path)
        date = datetime.datetime.now().strftime('%Y-%m-%d')
        post = BlogPost(title=title, content=content, image=image_filename, date=date, user_id=session['user_id'], tags=tags)
        db.session.add(post)
        db.session.commit()
        flash('Blog post created!')
        return redirect(url_for('index'))
    return render_template('create_post.html')
# View single post, add comment, like, edit/delete
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    author = User.query.get(post.user_id)
    user = User.query.get(session.get('user_id')) if session.get('user_id') else None
    if request.method == 'POST':
        if 'comment' in request.form:
            content = request.form['comment']
            comment = Comment(content=content, date=datetime.datetime.now().strftime('%Y-%m-%d'), user_id=session['user_id'], post_id=post.id)
            db.session.add(comment)
            db.session.commit()
            flash('Comment added!')
        elif 'like' in request.form:
            if not Like.query.filter_by(user_id=session['user_id'], post_id=post.id).first():
                like = Like(user_id=session['user_id'], post_id=post.id)
                db.session.add(like)
                db.session.commit()
                flash('Liked!')
        elif 'edit' in request.form and user and user.id == post.user_id:
            return redirect(url_for('edit_post', post_id=post.id))
        elif 'delete' in request.form and user and user.id == post.user_id:
            db.session.delete(post)
            db.session.commit()
            flash('Post deleted!')
            return redirect(url_for('index'))
    comments = post.comments.order_by(Comment.id.desc()).all()
    like_count = post.likes.count()
    return render_template('view_post.html', post=post, author=author, comments=comments, like_count=like_count, user=user)

# Edit post
@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    if session.get('user_id') != post.user_id:
        flash('You can only edit your own posts.')
        return redirect(url_for('index'))
    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        post.tags = request.form.get('tags', '')
        image_file = request.files.get('image')
        if image_file and image_file.filename:
            image_filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image_file.save(image_path)
            post.image = image_filename
        db.session.commit()
        flash('Post updated!')
        return redirect(url_for('view_post', post_id=post.id))
    return render_template('edit_post.html', post=post)
# Change password
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to change your password.')
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        old = request.form['old_password']
        new = request.form['new_password']
        if check_password_hash(user.password_hash, old):
            user.password_hash = generate_password_hash(new)
            db.session.commit()
            flash('Password changed!')
            return redirect(url_for('profile', user_id=user.id))
        else:
            flash('Old password incorrect.')
    return render_template('change_password.html')
# Password reset (basic)
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            user.password_hash = generate_password_hash('newpassword123')
            db.session.commit()
            flash('Password reset! New password: newpassword123')
            return redirect(url_for('login'))
        else:
            flash('Email not found.')
    return render_template('reset_password.html')
# Edit profile route
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to edit your profile.')
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.first_name = request.form['first_name']
        user.role = request.form['role']
        profile_pic_file = request.files.get('profile_pic')
        if profile_pic_file and profile_pic_file.filename:
            profile_pic_filename = secure_filename(profile_pic_file.filename)
            profile_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_pic_filename)
            profile_pic_file.save(profile_pic_path)
            user.profile_pic = profile_pic_filename
        db.session.commit()
        flash('Profile updated!')
        return redirect(url_for('profile', user_id=user.id))
    return render_template('edit_profile.html', user=user)
# View all users, filter/sort
@app.route('/users')
def users():
    role = request.args.get('role', None)
    sort = request.args.get('sort', 'first_name')
    query = User.query
    if role:
        query = query.filter_by(role=role)
    if sort == 'first_name':
        query = query.order_by(User.first_name)
    elif sort == 'role':
        query = query.order_by(User.role)
    users = query.all()
    return render_template('users.html', users=users)
# User dashboard
@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to view dashboard.')
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    posts = BlogPost.query.filter_by(user_id=user_id).order_by(BlogPost.id.desc()).all()
    comments = Comment.query.filter_by(user_id=user_id).order_by(Comment.id.desc()).all()
    likes = Like.query.filter_by(user_id=user_id).count()
    return render_template('dashboard.html', user=user, posts=posts, comments=comments, likes=likes)
# Admin page for teacher
@app.route('/admin')
def admin():
    user_id = session.get('user_id')
    user = User.query.get(user_id) if user_id else None
    if not user or not user.is_teacher:
        flash('Admin access only.')
        return redirect(url_for('index'))
    all_users = User.query.all()
    all_posts = BlogPost.query.all()
    return render_template('admin.html', users=all_users, posts=all_posts)

# Profile image upload for accounts (optional, for future expansion)
# You can add a similar route for users to update their profile pic if needed.


if __name__ == '__main__':
    if not os.path.exists('classsite.db'):
        with app.app_context():
            db.create_all()
    app.run(debug=True)
