from flask import Flask, render_template, redirect, url_for, flash, get_flashed_messages, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("BLOG_APP_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
ADMIN = os.getenv("ADMIN")

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# LOGIN MODULE CONFIGURATION
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Gravatar Images
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    post = relationship("BlogPost", back_populates="comments")
# db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id == ADMIN or current_user.is_authenticated:
            return f(*args, **kwargs)
        return abort(403)
    return decorated_function

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, admin=ADMIN)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        if User.query.filter_by(email=register_form.email.data).first():
            flash("You've already signed up with that email, log in instead!")
            # Redirect to /login route.
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(register_form.password.data, method="pbkdf2:sha256", salt_length=8)
        new_user = User(
            email=register_form.email.data,
            password=hashed_password,
            name=register_form.name.data
            )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_form, current_user=current_user, admin=ADMIN)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        password = login_form.password.data
        user = User.query.filter_by(email=login_form.email.data).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("The password doesn't match, please try again.")
                return redirect(url_for("login"))
        else:
            flash("The email does not exist, Please try again.")
            return redirect(url_for("login"))
    return render_template("login.html", form=login_form, current_user=current_user, admin=ADMIN)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=comment_form.comment_text.data,
                comment_author=current_user,
                post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        else:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

    return render_template("post.html", form=comment_form, post=requested_post, current_user=current_user, admin=ADMIN)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user, admin=ADMIN)


@app.route("/contact" ,methods=["GET", "POST"])
def contact():
    return render_template("contact.html", current_user=current_user, admin=ADMIN)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user, admin=ADMIN)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    if post.author_id == current_user.id or current_user.id == 1:
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            author=post.author.name,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))

        return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user, admin=ADMIN)
    return abort(403)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    if post_to_delete.author_id == current_user.id or current_user.id == 1:
        db.session.delete(post_to_delete)
        db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=False)
