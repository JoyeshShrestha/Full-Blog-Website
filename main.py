from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
import smtplib
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

import os
# from dotenv import load_dotenv
# load_dotenv()
'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''
password = os.environ.get("email_password") 
my_email = os.environ.get("email")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI')
db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)
# CONFIGURE TABLES



def admin_only(fun):
    @wraps(fun)
    def wrapper(*args,**kwargs):
        
        
        if current_user.id==1:
            return fun(*args,**kwargs)
        else:
            return abort(403)
               
    return wrapper   


# TODO: Create a User table for all your registered users. 

class User(UserMixin,db.Model):
    __tablename__="users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = relationship("BlogPost",back_populates = "author")
    comments = relationship("Comment",back_populates="comment_author")
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User",back_populates = "posts")
    img_url = db.Column(db.String(250), nullable=False)
    comment = relationship("Comment",back_populates="parent_post")

class Comment(db.Model):
    __tablename__="comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User",back_populates = "comments")
    post_id = db.Column(db.Integer,db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost",back_populates="comment")

with app.app_context():
    db.create_all()


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register',methods = ["GET","POST"])
def register():
    form = RegisterForm()
    if request.method == "POST":
        email = request.form["email"]
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login')) 
        if not user:
            register = User(
                email = email,
                password = generate_password_hash(request.form["password"],method='pbkdf2:sha256',salt_length=8),
                name = request.form["name"]
            )
            db.session.add(register)
            db.session.commit()
            return redirect(url_for('login')) 
        
    return render_template("register.html",form = form)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None) 
# TODO: Retrieve a user from the database based on their email. 
@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if request.method == "POST":
        email = request.form["email"]
        result = db.session.execute(db.select(User).where(User.email==email))
        user=result.scalar()
        if not user:
            flash("There is no such email")
        else:
            if check_password_hash(user.password,request.form["password"]):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Incorrect Password")
    return render_template("login.html",form=form,logged_in=False)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    
    if current_user.is_authenticated:
        return render_template("index.html", all_posts=posts,logged_in = current_user.is_authenticated,login_id = current_user.id)

    return render_template("index.html", all_posts=posts,logged_in = current_user.is_authenticated)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>",methods=["GET","POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment = CommentForm()
    if request.method == "POST":
        if not current_user.is_authenticated:
            return redirect("login")
        commenting = Comment(
                
                text = request.form["comment"],
                comment_author=current_user,
                parent_post = requested_post


            )
        db.session.add(commenting)
        db.session.commit()
       
    comment_list =db.session.execute(db.select(Comment).where(post_id ==post_id)).scalars()
    if current_user.is_authenticated:
        return render_template("post.html", post=requested_post, logged_in = current_user.is_authenticated, login_id = current_user.id, comment_form = comment,comments=comment_list,gravatar=gravatar,login_email = current_user.email)

    return render_template("post.html", post=requested_post, logged_in = current_user.is_authenticated, comment_form = comment,comments=comment_list,gravatar=gravatar)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@login_required
# @admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in = current_user.is_authenticated,login_email = current_user.email)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True,login_email = current_user.email)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")

def send_email(name,email,phone,message):
        try:
            connection =smtplib.SMTP("smtp.gmail.com", port=587)

            connection.starttls()
            connection.login(user=my_email,password=password)
            connection.sendmail(
                from_addr = my_email, 
                to_addrs=my_email, 
                msg=f"Subject: {name} sends you email from website\n\nname: {name}\nemail: {email}\nphone number: {phone}\nmessage: {message}\nRegards, {name} ")
            connection.close()
            
        except:
            return False  
        else:
            return True 
@app.route('/contact',methods = ["GET","POST"])
def contact():
    if request.method == "GET":

        return render_template('contact.html')
    elif request.method=="POST":
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        message = request.form['message']
        if send_email(name,email,phone,message):
            return f"Successfully sent"
        else:
            return f"Error while sending email"
    return render_template("contact.html")



def add_security_headers(response):
    # HTTP Strict Transport Security
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Content Security Policy
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data: /static/; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"



    # X-Frame-Options
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'

    # X-Content-Type-Options
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Referrer Policy
    response.headers['Referrer-Policy'] = 'no-referrer'

    # Permissions Policy
    response.headers['Permissions-Policy'] = 'geolocation=(), midi=(), sync-xhr=()'

    return response

# Apply the security headers to all responses using the after_request decorator
app.after_request(add_security_headers)


if __name__ == "__main__":
    app.run(debug=False, port=5002)
