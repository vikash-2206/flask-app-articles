from flask import Flask,render_template,request,flash,redirect,url_for,session,logging
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form,StringField,TextAreaField,PasswordField,validators
from passlib.hash import sha256_crypt
from functools import wraps


app = Flask(__name__)

#Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'inferno22'
app.config['MYSQL_DB'] = 'flaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'


#init  MYSQl
mysql = MySQL(app)

#home-page
@app.route('/')
def index():
	return render_template('home.html')


#about page
@app.route('/about')
def about():
	return render_template('about.html')

#fetch articles
Articles = Articles()

#articles page
@app.route('/articles')
def articles():
	return render_template('articles.html', articles = Articles)

#access article directly through id number
@app.route('/articles/<string:id>/')
def article(id):
	return render_template('article.html', id=id)

#registration form
class RegisterForm(Form):
	name=StringField('Name',[validators.Length(min=1,max=50)])
	username = StringField('Username',[validators.Length(min=6, max=50)])
	email = StringField('Email',[validators.Length(min=6,max=50)])
	password = PasswordField('Password',[validators.DataRequired(),validators.EqualTo('confirm',message = 'Password do not match')])
	confirm = PasswordField('Confirm Password')
@app.route('/register',methods = ['GET','POST'])
def register():
	form =  RegisterForm(request.form)
	if request.method == 'POST' and form.validate():
		#wt form
		name = form.name.data
		email = form.email.data
		username = form.username.data
		password = sha256_crypt.encrypt(str(form.password.data))
		cur= mysql.connection.cursor()
		cur.execute("INSERT INTO users(name,email,username,password) VALUES(%s,%s,%s,%s)",(name,email,username,password))
		
		mysql.connection.commit()

		cur.close()

		flash('you are now registered and can log-in now', 'success')
		return redirect(url_for('login'))
	return render_template('register.html', form = form)

#user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash(' Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


@app.route('/logout')
@is_logged_in
def logout():
	session.clear()
	flash('logged out','success')
	return render_template('login.html')

@app.route('/dashboard')
@is_logged_in
def dashboard():
	return render_template('dashboard.html')
if __name__ == '__main__':
	app.secret_key='secret123'
	app.run(debug=True)