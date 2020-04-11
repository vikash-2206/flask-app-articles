from flask import Flask,render_template,request,flash,redirect,url_for,session,logging
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form,StringField,TextAreaField,PasswordField,validators
from passlib.hash import sha256_crypt


app = Flask(__name__)

#Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'inferno22'
app.config['MYSQL_DB'] = 'flaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'


#init  MYSQl
mysql = MySQL(app)

@app.route('/')
def index():
	return render_template('home.html')

@app.route('/about')
def about():
	return render_template('about.html')

Articles = Articles()
@app.route('/articles')
def articles():
	return render_template('articles.html', articles = Articles)

@app.route('/articles/<string:id>/')
def article(id):
	return render_template('article.html', id=id)

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
		name = form.name.data
		email = form.email.data
		username = form.username.data
		password = sha256_crypt.encrypt(str(form.password.data))
		cur= mysql.connection.cursor()
		cur.execute("INSERT INTO users(name,email,username,password) VALUES(%s,%s,%s,%s)",(name,email,username,password))
		
		mysql.connection.commit()

		cur.close()

		flash('you are now registered and can log-in now', 'success')
		return redirect(url_for('index'))
	return render_template('register.html', form = form)

if __name__ == '__main__':
	app.secret_key='secret123'
	app.run(debug=True)