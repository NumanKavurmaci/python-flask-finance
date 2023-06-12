import os
import re

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    user_id = session["user_id"]

    cash = db.execute("SELECT cash FROM users WHERE id=?", user_id)[0]["cash"]
    rows = db.execute(
        "SELECT symbol, SUM(shares) AS total_shares, price FROM transactions WHERE user_id=? GROUP BY symbol",
        user_id
    )

    portfolio = []

    for row in rows:
        quote = lookup(row["symbol"])

        value = quote["price"] * row["total_shares"]

        holding = {
            "symbol": row["symbol"],
            "shares": row["total_shares"],
            "price": quote["price"],
            "value": value,
        }
        portfolio.append(holding)

    total_value = sum(holding["value"] for holding in portfolio) + cash

    return render_template("index.html", portfolio=portfolio, cash=cash, total_value=total_value)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol or not shares:
            return apology("Please provide symbol and shares", 400)

        try:
            shares = int(shares)
            if shares <= 0:
                return apology("Shares must be a positive integer", 400)
        except ValueError:
            return apology("Shares must be a valid integer", 400)

        # Fetch stock price using the lookup function
        quote = lookup(symbol)
        if not quote:
            return apology("Failed to fetch stock price", 500)
        stock_price = quote["price"]
        total_cost = stock_price * shares

        user_id = session["user_id"]
        user = db.execute("SELECT * FROM users WHERE id = ?", user_id)[0]

        if user["cash"] < total_cost:
            return apology("Insufficient funds to make the purchase", 400)

        # Update the user's account balance if the purchase is successful
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_cost, user_id)

        # Store the purchase details in the database
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            user_id,
            symbol,
            shares,
            stock_price
        )

        # Redirect the user to a success page or display a success message
        return redirect("/")

    else:
        # Render the buy.html template for GET requests
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    user_id = session["user_id"]
    rows = db.execute(
        "SELECT symbol, shares, price, timestamp, CASE WHEN shares < 0 THEN 'Sold' ELSE 'Bought' END AS action FROM transactions WHERE user_id=? ORDER BY timestamp DESC",
        user_id
    )

    transactions = []
    for row in rows:
        transaction = {
            "symbol": row["symbol"],
            "shares": abs(row["shares"]),  # Take the absolute value for display
            "price": row["price"],
            "total": abs(row["shares"]) * row["price"],  # Calculate the total value
            "timestamp": row["timestamp"],
            "action": row["action"]
        }
        transactions.append(transaction)

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        symbol= request.form.get("symbol")
        if not symbol:
            return apology("Please provide a stock symbol")

        stock= lookup(symbol)
        if not stock:
            return apology("Stock symbol not found")

        return render_template("quoted.html", stock=stock)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Ensure username was submitted
        username = request.form.get("username")
        if not username:
            return apology("Username is required")

        # Ensure password was submitted
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not password or not confirmation:
            return apology("Password and confirmation are required")

        # Ensure passwords match
        if password != confirmation:
            return apology("Passwords do not match")

        # Check if the username already exists
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) > 0:
            return apology("Username already exists")

        # Ensure password meets complexity criteria
        if not re.search(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$", password):
            return apology("Password must be at least 8 characters long and contain at least one letter, one number, and one special character (@$!%*#?&).")

        # Insert the new user into the database
        hash_password = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username,
                   hash=hash_password)

        # Redirect user to login page or any other desired page
        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # Validate inputs
        if not symbol:
            return apology("Symbol is required")
        if shares <= 0:
            return apology("Shares must be a positive integer")

        user_id = session["user_id"]

        # Check if the user owns the selected stock
        row = db.execute(
            "SELECT SUM(shares) AS total_shares FROM transactions WHERE user_id=? AND symbol=?",
            user_id,
            symbol
        )[0]
        total_shares = row["total_shares"]

        if total_shares is None or shares > abs(total_shares):
            return apology("You do not own that many shares of the stock")

        quote = lookup(symbol)
        if not quote:
            return apology("Invalid symbol")

        # Calculate the total sell value
        sell_value = quote["price"] * shares

        # Update user's cash balance
        db.execute("UPDATE users SET cash = cash + ? WHERE id=?", sell_value, user_id)

        # Insert a negative transaction for selling the shares
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            user_id,
            symbol,
            -shares,
            quote["price"]
        )

        return redirect("/")
    else:
        user_id = session["user_id"]

        # Fetch the symbols the user owns
        rows = db.execute(
            "SELECT DISTINCT symbol FROM transactions WHERE user_id = ? AND shares > 0",
            user_id
        )
        symbols = [row["symbol"] for row in rows]
        return render_template("sell.html", symbols=symbols)


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    if request.method == "POST":
        password = request.form.get("password")
        user_id = session["user_id"]
        rows = db.execute("SELECT hash FROM users WHERE id=?", user_id)

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            flash("Incorrect password. Account not deleted.")
            return redirect("/")

        db.execute("DELETE FROM users WHERE id=?", user_id)
        flash("Account successfully deleted!")
        return redirect("/")
    else:
        return render_template("delete.html")


@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    if request.method=="POST":
        current=request.form.get("current_password")
        new=request.form.get("new_password")
        confirm=request.form.get("confirm_password")
        if not re.search(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$", new):
            return apology("New password does not meet complexity criteria")

        user_id=session["user_id"]
        rows=db.execute("SELECT hash FROM users WHERE id=?",user_id)

        if len(rows)!=1 or not check_password_hash(rows[0]["hash"], current):
            return apology("Incorrect current password")
        if new != confirm:
            return apology("Passwords do not match")
        if new == current:
            return apology("New password cannot be the same as the previous one")
        new_hash = generate_password_hash(new)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, user_id)

        flash("Password successfully changed!")
        return redirect("/")
    else:
        return render_template("changepassword.html")
def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    if request.method == "POST":
        amount = request.form.get("amount")
        try:
            amount = float(amount)
        except ValueError:
            return apology("Invalid amount")

        if amount <= 0:
            return apology("Amount must be a positive number")

        user_id = session["user_id"]
        db.execute("UPDATE users SET cash=cash+? WHERE id=?", amount, user_id)

        flash("Cash successfully added!")
        return redirect("/")

    else:
        return render_template("add_cash.html")

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

