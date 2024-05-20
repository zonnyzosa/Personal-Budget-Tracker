from flask import render_template, url_for, flash, redirect, request
from flask_login import login_user, current_user, logout_user, login_required
from app import app, db, bcrypt
from app.forms import RegistrationForm, LoginForm, ExpenseForm, IncomeForm
from app.models import User, Expense, Income
import matplotlib.pyplot as plt
import io
import base64

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/profile")
@login_required
def profile():
    return render_template('profile.html', title='Profile')

@app.route("/expense/new", methods=['GET', 'POST'])
@login_required
def new_expense():
    form = ExpenseForm()
    if form.validate_on_submit():
        expense = Expense(description=form.description.data, amount=form.amount.data, author=current_user)
        db.session.add(expense)
        db.session.commit()
        flash('Your expense has been added!', 'success')
        return redirect(url_for('home'))
    return render_template('create_expense.html', title='New Expense', form=form, legend='New Expense')

@app.route("/income/new", methods=['GET', 'POST'])
@login_required
def new_income():
    form = IncomeForm()
    if form.validate_on_submit():
        income = Income(description=form.description.data, amount=form.amount.data, author=current_user)
        db.session.add(income)
        db.session.commit()
        flash('Your income has been added!', 'success')
        return redirect(url_for('home'))
    return render_template('create_income.html', title='New Income', form=form, legend='New Income')

@app.route("/")
@login_required
def home():
    expenses = Expense.query.filter_by(author=current_user).all()
    incomes = Income.query.filter_by(author=current_user).all()
    return render_template('home.html', expenses=expenses, incomes=incomes)

@app.route("/expense/<int:expense_id>/update", methods=['GET', 'POST'])
@login_required
def update_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.author != current_user:
        abort(403)
    form = ExpenseForm()
    if form.validate_on_submit():
        expense.description = form.description.data
        expense.amount = form.amount.data
        db.session.commit()
        flash('Your expense has been updated!', 'success')
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.description.data = expense.description
        form.amount.data = expense.amount
    return render_template('create_expense.html', title='Update Expense', form=form, legend='Update Expense')

@app.route("/income/<int:income_id>/update", methods=['GET', 'POST'])
@login_required
def update_income(income_id):
    income = Income.query.get_or_404(income_id)
    if income.author != current_user:
        abort(403)
    form = IncomeForm()
    if form.validate_on_submit():
        income.description = form.description.data
        income.amount = form.amount.data
        db.session.commit()
        flash('Your income has been updated!', 'success')
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.description.data = income.description
        form.amount.data = income.amount
    return render_template('create_income.html', title='Update Income', form=form, legend='Update Income')

@app.route("/expense/<int:expense_id>/delete", methods=['POST'])
@login_required
def delete_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.author != current_user:
        abort(403)
    db.session.delete(expense)
    db.session.commit()
    flash('Your expense has been deleted!', 'success')
    return redirect(url_for('home'))

@app.route("/income/<int:income_id>/delete", methods=['POST'])
@login_required
def delete_income(income_id):
    income = Income.query.get_or_404(income_id)
    if income.author != current_user:
        abort(403)
    db.session.delete(income)
    db.session.commit()
    flash('Your income has been deleted!', 'success')
    return redirect(url_for('home'))

@app.route("/report")
@login_required
def report():
    expenses = Expense.query.filter_by(author=current_user).all()
    incomes = Income.query.filter_by(author=current_user).all()

    expense_amounts = [expense.amount for expense in expenses]
    income_amounts = [income.amount for income in incomes]
    expense_labels = [expense.description for expense in expenses]
    income_labels = [income.description for income in incomes]

    fig, ax = plt.subplots()
    ax.pie(expense_amounts, labels=expense_labels, autopct='%1.1f%%')
    plt.title('Expenses')
    plt.savefig('app/static/expense_report.png')

    fig, ax = plt.subplots()
    ax.pie(income_amounts, labels=income_labels, autopct='%1.1f%%')
    plt.title('Income')
    plt.savefig('app/static/income_report.png')

    return render_template('report.html', title='Report', expense_url='static/expense_report.png', income_url='static/income_report.png')
