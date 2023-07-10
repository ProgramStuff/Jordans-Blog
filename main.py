from flask import Flask, render_template, redirect, url_for, flash, abort, jsonify, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey, Integer
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os
from dotenv.main import load_dotenv


app = Flask(__name__)
load_dotenv()
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)


# GRAVATAR IMAGES
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    blogs = relationship('BlogPost', backref='user')
    comments = relationship('Comment', backref='user')


# TEST NEW DATA BASE RELATIONSHIPS
# CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"

    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey('users.id'), nullable=False)
    comments = relationship('Comment', backref='blogpost')


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey('users.id'), nullable=False)
    blog_id = db.Column('blog_id', db.Integer, db.ForeignKey('blog_posts.id'), nullable=False)



with app.app_context():
    db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return abort(403)

    return decorated_function


@login_manager.user_loader
def load_user(user_id: int):
    return User.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        all_users = db.session.query(User).all()
        if not all_users:
            hashed_pass = generate_password_hash(form.password.data, salt_length=8)
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=hashed_pass
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(load_user(user_id=new_user.id))
            return redirect("/")
        for user in all_users:
            if user.email != form.email.data:
                hashed_pass = generate_password_hash(form.password.data, salt_length=8)
                new_user = User(
                    name=form.name.data,
                    email=form.email.data,
                    password=hashed_pass
                )
                db.session.add(new_user)
                db.session.commit()
                login_user(load_user(user_id=new_user.id))
                return redirect("/")
            else:
                flash("That email is already registered. Please login.")
                return redirect("/login")
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    correct_email = False
    if form.validate_on_submit():
        all_users = db.session.query(User).all()
        for profile in all_users:
            if profile.email == form.email.data:
                correct_email = True
                current_account = profile
        if correct_email:
            if check_password_hash(current_account.password, form.password.data):
                login_user(load_user(user_id=current_account.id))
                return redirect('/')
            else:
                flash("Incorrect password. Try again.")
        else:
            flash("Email does not exist. Please try again.")
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    blog_comments = db.session.query(Comment).all()
    all_users = db.session.query(User).all()

    if current_user.is_authenticated:
        if form.validate_on_submit():
            new_comment = Comment(
                text=form.comment.data,
                user_id=current_user.id,
                blog_id=post_id
            )
            db.session.add(new_comment)
            db.session.commit()
        else:
            redirect("/login")
    return render_template("post.html", post=requested_post, form=form, comments=blog_comments,
                           post_id=post_id, users=all_users)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            user_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
