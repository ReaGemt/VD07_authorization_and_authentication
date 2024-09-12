from flask import render_template, url_for, redirect, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash
from app import db
from app.models import User
from app.forms import LoginForm, RegistrationForm, UpdateProfileForm
from flask import Blueprint

main = Blueprint('main', __name__)

@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        print("Форма прошла валидацию")  # Отладка: форма прошла валидацию
        print(f"Новое имя пользователя: {form.username.data}")
        print(f"Новый email: {form.email.data}")

        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.password.data:
            current_user.password_hash = generate_password_hash(form.password.data)
        db.session.commit()

        flash('Ваш профиль был обновлен!', 'success')
        return redirect(url_for('main.profile'))

    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email

    return render_template('profile.html', form=form)


@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.welcome'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('main.welcome'))
        else:
            flash('Ошибка входа. Пожалуйста, проверьте email и пароль.', 'danger')
    return render_template('login.html', form=form)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.welcome'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Ваш аккаунт был создан! Теперь вы можете войти в систему.', 'success')
        login_user(user)
        return redirect(url_for('main.welcome'))
    return render_template('register.html', form=form)

@main.route('/welcome')
@login_required
def welcome():
    return render_template('welcome.html')

@main.route('/')
def home():
    return redirect(url_for('main.login'))
