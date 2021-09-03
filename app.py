import sqlite3
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask.helpers import url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from supplement import apology, login_required

import string
import random

from datetime import datetime, timedelta
from time import sleep, localtime, strftime

from flask_mail import Mail, Message

from threading import Timer, Thread


# Configure application
app = Flask(__name__)

# Configure automated email sender:
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = ""
app.config['MAIL_PASSWORD'] = ""
app.config['MAIL_DEFAULT_SENDER'] = ""
mail = Mail(app)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# A db connection function
def setup_connection():
    connection = sqlite3.connect("schedge.db", isolation_level=None)
    connection.row_factory = sqlite3.Row 
    return connection.cursor()

# Generate 6-digit alphanumeric codes
def gen_passcode():
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 6))    
    return code

# Ensure the code generated is unique everytime
def pass_code_unique():  
    c = setup_connection()

    code = gen_passcode()
    # Check if the code generated has been used before
    c.execute(''' SELECT passcode FROM all_tables WHERE 
                passcode = ?''', 
                (code, ))
    pass_code_dict = c.fetchall()
    # If used code is generated then generate a new one (recursion)
    if len(pass_code_dict) != 0:
        code = pass_code_unique()
    else:    
        return code
    return code


# Send reminder emails to subs and admins at that particular time
# It's activated as a separate thread via check_reminders()
def send_emails(sub_recipients, admin_recipients, tasks_recipients, current_day, current_time, current_date_formatted):
    c = setup_connection()
    
    with app.app_context():
        with mail.connect() as conn:
            # Send to subscribers
            for i in range(len(sub_recipients)):
                if not sub_recipients[i][current_day] or sub_recipients[i][current_day] == None:
                    continue
                else:    
                    message = "Schedge Reminder:  %s at %s" % (sub_recipients[i][current_day], sub_recipients[i]["from_time"])
                    subject = "Hello, %s..! It's a reminder from Schedge." % sub_recipients[i]["user_name"]
                    msg = Message(recipients=[sub_recipients[i]["email"]],
                                    body=message,
                                    subject=subject)

                    c.execute(''' SELECT * FROM sent_emails WHERE 
                                sent_date=? AND sent_time=? AND sent_msg=?AND
                                recipient_email=?''',
                                (current_date_formatted, current_time, message, sub_recipients[i]["email"]))
                    sent_check = c.fetchall()
                    if len(sent_check) == 0:
                        c.execute(''' INSERT INTO sent_emails 
                                    VALUES(?, ?, ?, ?)''',
                                (current_date_formatted, current_time, message, sub_recipients[i]["email"]))
                        conn.send(msg)
                    else:
                        continue

            # Send to admins
            for j in range(len(admin_recipients)):
                if not admin_recipients[j][current_day] or admin_recipients[j][current_day] == None:
                    continue
                else:    
                    message = "Schedge Reminder:  %s at %s" % (admin_recipients[j][current_day], admin_recipients[j]["from_time"])
                    subject = "Hello, %s..! It's a reminder from Schedge." % admin_recipients[j]["username"]
                    msg = Message(recipients=[admin_recipients[j]["email"]],
                                    body=message,
                                    subject=subject)

                    c.execute(''' SELECT * FROM sent_emails WHERE 
                                sent_date=? AND sent_time=? AND sent_msg=?AND
                                recipient_email=?''',
                                (current_date_formatted, current_time, message, admin_recipients[j]["email"]))
                    sent_check = c.fetchall()
                    if len(sent_check) == 0:
                        c.execute(''' INSERT INTO sent_emails 
                                    VALUES(?, ?, ?, ?)''',
                                (current_date_formatted, current_time, message, admin_recipients[j]["email"]))
                        conn.send(msg)
                    else:
                        continue

            # Send to tasks tables admins
            for k in range(len(tasks_recipients)):
                message = "Schedge Task Reminder:  %s at %s" % (tasks_recipients[k]["task"], tasks_recipients[k]["time"])
                subject = "Hello, %s..! It's a task reminder from Schedge." % tasks_recipients[k]["username"]
                msg = Message(recipients=[tasks_recipients[k]["email"]],
                                body=message,
                                subject=subject)
        
                c.execute(''' SELECT * FROM sent_emails WHERE 
                            sent_date=? AND sent_time=? AND sent_msg=?AND
                            recipient_email=?''',
                            (current_date_formatted, current_time, message, tasks_recipients[k]["email"]))
                sent_check = c.fetchall()
                if len(sent_check) == 0:
                    c.execute(''' INSERT INTO sent_emails 
                                VALUES(?, ?, ?, ?)''',
                            (current_date_formatted, current_time, message, tasks_recipients[k]["email"]))
                    conn.send(msg)
                else:
                    continue

# Check every 59 seconds if a reminder is due sending
def check_reminders():
    # Using Timer from threading; This creates a new thread everytime and so is not recursion
    timer = Timer(59.0, check_reminders)
    # Daemonic thread it is, as it will also stop when main thread is stoppped.
    timer.daemon = True
    # Start this thread of checking every 59 seconds
    timer.start()
    t = localtime()
    current_date = datetime.today()
    current_time = strftime("%H:%M", t)
    current_day = datetime.weekday(current_date) + 3

    date_formatted = datetime.now() 
    current_date_formatted = date_formatted.strftime("%Y-%m-%d")

    c = setup_connection()

    # Get the subs and content info
    c.execute('''SELECT email, user_name, from_time, mday, tday, wday, thday, fday, sday, suday
                FROM
                (SELECT * FROM all_users
                JOIN 
                (SELECT all_subscriptions.user_name, 
                week_table.from_time, week_table.mday, week_table.tday, week_table.wday, week_table.thday, week_table.fday, week_table.sday, week_table.suday
                FROM all_subscriptions 
                INNER JOIN week_table 
                ON all_subscriptions.table_id = week_table.table_id 
                WHERE remind_time = ?)
                ON all_users.username = user_name)''',(current_time, ))
    sub_recipients = c.fetchall()
    # Get the admins and content info
    c.execute(''' SELECT email, username, from_time, mday, tday, wday, thday, fday, sday, suday
                FROM
                (SELECT * FROM all_users
                JOIN 
                (SELECT all_tables.admin, 
                week_table.from_time, week_table.mday, week_table.tday, week_table.wday, week_table.thday, week_table.fday, week_table.sday, week_table.suday
                FROM all_tables 
                INNER JOIN week_table 
                ON all_tables.table_id = week_table.table_id 
                WHERE remind_time = ?)
                ON all_users.id = admin) ''', (current_time, ))
    admin_recipients = c.fetchall()
    # Get the tasks admin and content info
    c.execute(''' SELECT email, username, date, time, task
                FROM
                (SELECT * FROM all_users
                JOIN 
                (SELECT all_tables.admin, 
                tasks_table.date, tasks_table.time, tasks_table.task
                FROM all_tables 
                INNER JOIN tasks_table 
                ON all_tables.table_id = tasks_table.table_id 
                WHERE task_remind_time = ? AND date = ?)
                ON all_users.id = admin) ''', (current_time, current_date_formatted))
    tasks_recipients = c.fetchall()

    if len(sub_recipients) != 0 or len(admin_recipients) != 0 or len(tasks_recipients) != 0:
        # If it is the time, then start the email thread
        email_thread = Thread(target=send_emails, args=(sub_recipients, admin_recipients, tasks_recipients, current_day, current_time, current_date_formatted))
        email_thread.start()
        

# My Day: tasks for today after login
@app.route("/")
@login_required
def my_day():
    c = setup_connection()

    c.execute("SELECT username FROM all_users WHERE id = ?", (session["user_id"], ))
    user_name = c.fetchall()

    current_date = datetime.today()
    current_day = datetime.weekday(current_date)
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']


    date_formatted = datetime.now() 
    current_date_formatted = date_formatted.strftime("%Y-%m-%d")

    # Get the times and tasks
    c.execute(''' SELECT time, task FROM tasks_table WHERE
                table_id IN
                (SELECT table_id FROM all_tables WHERE 
                 admin = ? AND dayweek = ?)
                AND date = ? ''',
                (session["user_id"], 1, current_date_formatted))
    my_day_tasks = c.fetchall()
    my_day_count = len(my_day_tasks)  

    return render_template("my_day.html", user_name=user_name, my_day_tasks=my_day_tasks, my_day_count=my_day_count, current_date_formatted=current_date_formatted, current_day=current_day, days=days)          

# Display all week tables
@app.route("/all")
@login_required
def all():
    c = setup_connection()

    c.execute("SELECT username FROM all_users WHERE id = ?", (session["user_id"], ))
    user_name = c.fetchall()

    c.execute('''SELECT all_tables.*, all_users.username
                FROM all_tables 
                JOIN 
                all_users
                ON all_tables.admin=all_users.id
                WHERE table_id IN 
                (SELECT table_id FROM all_subscriptions WHERE user_name = ?)
                OR admin = ? AND dayweek != ?''', (user_name[0]["username"], session["user_id"], 1))
    all_tabs = c.fetchall()
    all_count = len(all_tabs)

    return render_template("all.html", all_tabs=all_tabs, all_count=all_count, user_name=user_name)

# Login User
@app.route("/login", methods=["GET", "POST"])
def login():
    c = setup_connection()

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Must provide username.", category="message")
            return redirect("/login")
        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Must provide password.", category="message")
            return redirect("/login")

        # Query database for username
        c.execute("SELECT * FROM all_users WHERE username = ?",
                    (request.form.get("username"), ))
        current_user = c.fetchall()
        # Ensure username exists and password is correct
        if len(current_user) != 1 or not check_password_hash(current_user[0]["hash"], request.form.get("password")):
            flash("Invalid username and/or password.", category="message")
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = current_user[0]["id"]

        flash("Log In successful.", category="message")
        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("login.html")

# Register User
@app.route("/register", methods=["GET", "POST"])
def register():
    c = setup_connection()

    # User submitted to register.html via POST request method
    if request.method == "POST":
        # Check for blank input fields
        if not request.form.get("username"):
            flash("Must provide username.", category="message")
            return redirect("/register")
        elif not request.form.get("password"):
            flash("Must provide password.", category="message")
            return redirect("/register")
        elif not request.form.get("confirmation"):
            flash("Must confirm password.", category="message")
            return redirect("/register")
        elif not request.form.get("email"):
            flash("Must provide an email.", category="message")
            return redirect("/register")

        # Query for the entered username or email if already exists in db
        c.execute('''SELECT * FROM all_users WHERE username = ?''',
                                (request.form.get("username"), ))
        check_user = c.fetchall()
        c.execute('''SELECT * FROM all_users WHERE email = ?''',
                                (request.form.get("email"), ))
        check_email = c.fetchall()
        if len(check_user) != 0:
            flash("Username already exists.", category="message")
            return redirect("/register")
        elif len(check_email) != 0:
            flash("Email already exists.", category="message")
            return redirect("/register")
        # Entered password field and confirmation field must match exactly
        elif request.form.get("password") != request.form.get("confirmation"):
            flash("Passwords don't match.", category="message")
            return redirect("/register")
        # If all good then add the user to db
        else:
            c.execute('''INSERT INTO all_users(username, hash, email)
                         VALUES(?, ?, ?)''',
                        (request.form.get("username"),
                        generate_password_hash(request.form.get("password")), 
                        request.form.get("email")))

            # Redirect user to login with credentials just entered
            return redirect("/login")

    else:
        return render_template("register.html")


# Log user out
@app.route("/logout")
def logout():
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


# All Week Creations of User
@app.route("/creations")
@login_required
def creations():
    c = setup_connection()

    c.execute("SELECT username FROM all_users WHERE id = ?", (session["user_id"], ))
    user_name = c.fetchall()

    c.execute("SELECT * FROM all_tables WHERE admin = ? AND dayweek != ?", (session["user_id"], 1))
    creations = c.fetchall()
    creations_count = len(creations)

    return render_template("creations.html", creations=creations, creations_count=creations_count, user_name=user_name)


#  All Week Subscriptions of User
@app.route("/subscriptions")
@login_required
def subscriptions():
    c = setup_connection()

    c.execute("SELECT username FROM all_users WHERE id = ?", (session["user_id"], ))
    user_name = c.fetchall()

    c.execute('''SELECT all_tables.*, all_users.username
                FROM all_tables 
                JOIN 
                all_users
                ON all_tables.admin=all_users.id
                WHERE table_id IN 
                (SELECT table_id FROM all_subscriptions WHERE user_name = ?)
                ''', (user_name[0]["username"], ))

    subs = c.fetchall()
    subs_count = len(subs)

    return render_template("subscriptions.html", subs=subs, subs_count=subs_count, user_name=user_name)


# Create a new week table
@app.route("/new", methods=["POST"])
@login_required
def new():
    c = setup_connection()

    c.execute("SELECT username FROM all_users WHERE id = ?", (session["user_id"], ))
    user_name = c.fetchall()

    if request.method == "POST":
        # First check if same table name exists in the User's db
        c.execute(''' SELECT table_id FROM all_tables WHERE 
                    table_name = ? AND admin = ?''', 
                    (request.form.get("tab_name"), session["user_id"]))
        table_exists = c.fetchall()            
        if len(table_exists) != 0:
            flash("A table with same name exists in your creations.", category="message")
            return redirect("/creations")

        # If all good, then generate passcode
        passcode = pass_code_unique()

        c.execute(''' INSERT INTO all_tables (admin, member_count, table_name, dayweek, passcode)
                    VALUES(?, ?, ?, ?, ?) ''', 
                    (session["user_id"], 1, request.form.get("tab_name"), request.form.get("weekends"), passcode))
        
        # Redirect to the table page
        c.execute(''' SELECT table_id FROM all_tables 
                    WHERE table_name = ? AND admin = ? ''', (request.form.get("tab_name"), session["user_id"]))
        this_table_id = c.fetchall()            
            
        flash(f"New table created.", category="message")
        return redirect(url_for("table", table_id=this_table_id[0]["table_id"]))    




# Display week table
@app.route("/<int:table_id>")
@login_required
def table(table_id):
    c = setup_connection()

    c.execute("SELECT username FROM all_users WHERE id = ?", (session["user_id"], ))
    user_name = c.fetchall()

    # Stop users from entering unauthorized tables
    c.execute(''' SELECT table_id FROM all_tables WHERE admin = ?
                UNION 
                SELECT table_id FROM all_subscriptions WHERE user_name = ?''',
                (session["user_id"], user_name[0]["username"])) 
    all_table_id = c.fetchall()

    check = 0
    
    for i in range(len(all_table_id)):   
        if int(table_id) == all_table_id[i]["table_id"]:
            check = 1
            break
    if check == 0:
        return apology("Not your table..!", 403)  
    
    #--------------------------------------------------------
    c.execute(''' SELECT * FROM all_tables WHERE 
                table_id = ? ''', (table_id, ))
    table_info = c.fetchall()
    this_table={}
    
    column_names = ['from_time', 'till_time', 'mday', 'tday', 'wday', 'thday', 'fday', 'sday', 'suday']
    column = ['From', 'Till', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']

    c.execute(''' SELECT * FROM week_table WHERE
                    table_id = ?''', (table_id, ))
    this_table = c.fetchall()

    count_rows = len(this_table)    
    
    return render_template("table.html", this_table=this_table, table_info=table_info, user_name=user_name, count_rows=count_rows, column_names=column_names, column=column)


# Handles adding a new row to a week table
@app.route("/<int:table_id>/add_row", methods=["POST"])
@login_required
def add_row(table_id):
    c = setup_connection()

    if request.method == "POST":
        c.execute(''' SELECT * FROM all_tables WHERE 
                table_id = ? ''', (table_id, ))
        table_info = c.fetchall()

        
        min = int(request.form.get("remind_min"))
        remind =  datetime.strptime(request.form.get("from_time"), "%H:%M") - timedelta(minutes = min)
        remind_time = remind.strftime("%H:%M")
        
        if table_info[0]["admin"] == session["user_id"]:
            if table_info[0]["dayweek"] == 7:
                c.execute('''INSERT INTO week_table
                        (table_id, from_time, till_time, mday, tday, wday, thday, fday, sday, suday, remind_time)
                        VALUES(?, ? ,?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (table_id, request.form.get("from_time"), request.form.get("till_time"), 
                        request.form.get("mday"), request.form.get("tday"),request.form.get("wday"), 
                        request.form.get("thday"), request.form.get("fday"), request.form.get("sday"), 
                        request.form.get("suday"), remind_time))

            elif table_info[0]["dayweek"] == 6:
                c.execute('''INSERT INTO week_table
                        (table_id, from_time, till_time, mday, tday, wday, thday, fday, sday, remind_time) 
                        VALUES(?, ? ,?, ?, ?, ?, ?, ?, ?, ?)''',
                        (table_id, request.form.get("from_time"), request.form.get("till_time"), 
                        request.form.get("mday"), request.form.get("tday"),request.form.get("wday"), 
                        request.form.get("thday"), request.form.get("fday"), request.form.get("sday"), remind_time))

            elif table_info[0]["dayweek"] == 5:
                c.execute('''INSERT INTO week_table 
                        (table_id, from_time, till_time, mday, tday, wday, thday, fday, remind_time)
                        VALUES(?, ? ,?, ?, ?, ?, ?, ?, ?)''',
                        (table_id, request.form.get("from_time"), request.form.get("till_time"), 
                        request.form.get("mday"), request.form.get("tday"),request.form.get("wday"), 
                        request.form.get("thday"), request.form.get("fday"), remind_time))

            flash("New row added.", category="message")
            return redirect(url_for("table", table_id=table_info[0]["table_id"]))
        else:
            return apology("You aren't the table's admin..!", 403)
    

# Handles editing a row of a week table
@app.route("/<int:row_id>/edit_row", methods=["POST"])
@login_required
def edit_row(row_id):
    c = setup_connection() 

    if request.method == "POST":
        c.execute(''' SELECT admin, dayweek, table_name, table_id FROM all_tables WHERE table_id IN(
                    SELECT table_id FROM week_table WHERE 
                    row_id = ?) ''', (row_id, ))
        table_info = c.fetchall()

        min = int(request.form.get("remind_min"))
        remind =  datetime.strptime(request.form.get("from_time"), "%H:%M") - timedelta(minutes = min)
        remind_time = remind.strftime("%H:%M")

        if table_info[0]["admin"] == session["user_id"]:
            if table_info[0]["dayweek"] == 7:
                c.execute('''UPDATE week_table SET
                            from_time=?, till_time=?, mday=?, tday=?, wday=?, thday=?, fday=?, sday=?, suday=?, remind_time=?
                            WHERE row_id=?''',
                        (request.form.get("from_time"), request.form.get("till_time"), 
                        request.form.get("mday"), request.form.get("tday"),request.form.get("wday"), 
                        request.form.get("thday"), request.form.get("fday"), request.form.get("sday"), 
                        request.form.get("suday"), remind_time, row_id))

            elif table_info[0]["dayweek"] == 6:
                c.execute('''UPDATE week_table SET
                            from_time=?, till_time=?, mday=?, tday=?, wday=?, thday=?, fday=?, sday=?, remind_time=?
                            WHERE row_id=?''',
                        (request.form.get("from_time"), request.form.get("till_time"), 
                        request.form.get("mday"), request.form.get("tday"),request.form.get("wday"), 
                        request.form.get("thday"), request.form.get("fday"), request.form.get("sday"), remind_time, row_id))

            elif table_info[0]["dayweek"] == 5:
                c.execute('''UPDATE week_table SET
                            from_time=?, till_time=?, mday=?, tday=?, wday=?, thday=?, fday=?, remind_time=?
                            WHERE row_id=?''',
                        (request.form.get("from_time"), request.form.get("till_time"), 
                        request.form.get("mday"), request.form.get("tday"),request.form.get("wday"), 
                        request.form.get("thday"), request.form.get("fday"), remind_time, row_id))

            flash("Table updated.")
            return redirect(url_for("table", table_id=table_info[0]["table_id"]))
        else:
            return apology("You aren't the table's admin..!", 403)


# Handles deleting a row of a week table
@app.route("/<int:row_id>/delete_row")
@login_required
def delete_row(row_id):
    c = setup_connection() 
     
    # Check for unauthorized row deletions
    c.execute(''' SELECT row_id FROM week_table WHERE table_id IN(
                SELECT table_id FROM all_tables WHERE admin = ?)''',
                (session["user_id"], )) 
    all_row_id = c.fetchall()

    check = 0
    for i in range(len(all_row_id)):   
        if int(row_id) == all_row_id[i]["row_id"]:
            check = 1
            break
    if check == 0:
        return apology("Not your table..!", 403)

    # If all good then delete row  
    else:
        c.execute(''' SELECT * FROM all_tables WHERE table_id IN(
                    SELECT table_id FROM week_table WHERE 
                    row_id = ?) ''', (row_id, ))
        table_info = c.fetchall()

        c.execute(''' DELETE FROM week_table WHERE 
                    row_id = ? ''', (row_id, ))

        flash("Row deleted.", category="message")
        return redirect(url_for("table", table_id=table_info[0]["table_id"]))               


# Add a new participant for a week table
@app.route("/<int:table_id>/add_participant", methods=["POST"])
@login_required
def add_participant(table_id):
    c = setup_connection()

    if request.method == "POST":
        
        c.execute(''' SELECT * FROM all_tables WHERE table_id =? ''',
                    (table_id, ))
        table_info = c.fetchall()            
        # Check for credentials in db
        c.execute(''' SELECT id, username, email FROM all_users
                    WHERE username=? AND email=? ''',
                    (request.form.get("username"), request.form.get("email")))
        check_user = c.fetchall()
        if len(check_user) == 0:
            flash("Either aspirant not registered with Schedge or the credentials entered don't match.", category="message")
            return redirect(url_for("table", table_id=table_id))
        # Check for author's access
        elif check_user[0]["id"] == session["user_id"]:
            flash("You are the table's admin..!", category="message")
            return redirect(url_for("table", table_id=table_id))
        else:
            # Check if already a subscriber
            c.execute(''' SELECT user_name FROM all_subscriptions
                    WHERE user_name=? AND table_id=?''',
                    (request.form.get("username"), table_id))
            check_sub= c.fetchall()
            if len(check_sub) != 0:
                flash("Already a subscriber.", category="message")
                return redirect(url_for("table", table_id=table_id))
            
            # All good then add
            else:
                c.execute(''' INSERT INTO all_subscriptions
                            (user_name, table_id)
                            VALUES(?, ?)''',
                            (request.form.get("username"), table_id))
                
                c.execute(''' UPDATE all_tables SET
                            member_count = ? WHERE
                            table_id = ?''',
                            (table_info[0]["member_count"] + 1, table_id)) 

                flash("New participant added.", category="message")
                return redirect(url_for("table", table_id=table_id))                       


# Subscribe to a new week table via passcode
@app.route("/new_subscription", methods=["POST"])
@login_required
def new_subscription():
    c = setup_connection()

    c.execute(''' SELECT table_id, admin, member_count FROM all_tables WHERE
                passcode = ?''', (request.form.get("passcode"), ))
    table_check_info = c.fetchall()

    # Check passcode validity
    if len(table_check_info) == 0:
        flash("No table with this passcode.", category="message")
        return redirect("/subscriptions")
    # Check if the admin is trying to subscribe it's own table
    elif table_check_info[0]["admin"] == session["user_id"]:
        flash("You are the table's admin..!", category="message")
        return redirect("/creations")
    
    c.execute(''' SELECT username from all_users WHERE id = ? ''', (session["user_id"], ))
    user_name = c.fetchall()

    # Check if already a subscriber
    c.execute(''' SELECT user_name, table_id FROM all_subscriptions WHERE
                table_id = ? AND user_name = ?''', 
                (table_check_info[0]["table_id"], user_name[0]["username"]))
    check_sub = c.fetchall()
    if len(check_sub) != 0:
        flash("Already a subscriber.", category="message")
        return redirect(url_for("table", table_id=table_check_info[0]["table_id"]))
    
    # All good then subscribe
    else:
        # Generate a new passcode for that table and replace
        passcode = pass_code_unique()

        c.execute(''' INSERT INTO all_subscriptions(user_name, table_id)
                    VALUES(?, ?) ''',
                    (user_name[0]["username"], table_check_info[0]["table_id"]))  
        
        c.execute(''' UPDATE all_tables SET
                     member_count = ?, 
                     passcode = ? 
                     WHERE table_id = ?''',
                     (table_check_info[0]["member_count"] + 1, passcode, table_check_info[0]["table_id"]))              

        flash("Subscribed to this table.", category="message")
        return redirect(url_for("table", table_id = table_check_info[0]["table_id"]))
                

# Unsubscribe from a week table
@app.route("/<int:table_id>/unsubscribe")
@login_required
def unsubscribe(table_id):
    c = setup_connection()

    c.execute(''' SELECT username FROM all_users WHERE id = ? ''', (session["user_id"], ))
    user_name = c.fetchall()
    
    # Check for unauthorized access
    c.execute('''SELECT table_id FROM all_subscriptions WHERE user_name = ?''',
                (user_name[0]["username"], )) 
    all_sub_table_id = c.fetchall()

    check = 0
    for i in range(len(all_sub_table_id)):   
        if int(table_id) == all_sub_table_id[i]["table_id"]:
            check = 1
            break
    if check == 0:
        return apology("Not your subscription..!", 403)
    
    # All good then unsubscribe
    else:
        c.execute(''' DELETE FROM all_subscriptions WHERE 
                    user_name = ? AND table_id = ?''', 
                    (user_name[0]["username"], table_id))    

        c.execute(''' SELECT member_count FROM all_tables WHERE table_id = ? ''',
                    (table_id, ))  
        member_count = c.fetchall()

        c.execute(''' UPDATE all_tables SET
                    member_count = ? WHERE table_id = ? ''', 
                    (member_count[0]["member_count"] - 1, table_id))  

        flash("Unsubscribed", category="message")
        return redirect("/subscriptions")                   


# Delete a week table
@app.route("/<int:table_id>/delete_table")
@login_required
def delete_table(table_id):
    c = setup_connection()   

    # Check for unauthorized access
    c.execute(''' SELECT table_id FROM all_tables WHERE admin = ?''',
                (session["user_id"], )) 
    all_admin_table_id = c.fetchall()

    check = 0
    for i in range(len(all_admin_table_id)):   
        if int(table_id) == all_admin_table_id[i]["table_id"]:
            check = 1
            break
    if check == 0:
        return apology("Not your table..!", 403)
    
    # All good then deletes
    else:
        c.execute(''' DELETE FROM all_subscriptions WHERE table_id = ? ''', (table_id, ))

        c.execute(''' DELETE FROM week_table WHERE table_id = ? ''', (table_id, ))

        c.execute(''' DELETE FROM all_tables WHERE table_id = ? ''', (table_id, ))

        return redirect("/creations")            


# Profile page that shows username and email in use plus lets you change them
@app.route("/<int:profile_id>/username_email", methods=["GET", "POST"])
@login_required
def profile_username_email(profile_id):
    c = setup_connection()

    # Check for unauthorized access
    if int(profile_id) != session["user_id"]:
        return apology("Not your profile..!", 403)
    
    c.execute('''SELECT * FROM all_users WHERE id = ?''',
                    (session["user_id"], ))
    user_info = c.fetchall()

    if request.method == "POST":
        # If username change requested is actually a different one than previous
        if request.form.get("username") != user_info[0]["username"]:
            c.execute('''SELECT username FROM all_users WHERE username = ?''',
                                (request.form.get("username"), ))
            check_username = c.fetchall()
            # Then check if it's in use already
            if len(check_username) != 0:
                flash("A user with entered name already exists.", category="message")
                return redirect(url_for("profile_username_email", profile_id=profile_id))
        # Check the same for email
        elif request.form.get("email") != user_info[0]["email"]:
            c.execute('''SELECT email FROM all_users WHERE email = ?''',
                        (request.form.get("email"), ))
            check_email = c.fetchall()
            if len(check_email) != 0:
                flash("Entered email already exists.", category="message")
                return redirect(url_for("profile_username_email", profile_id=profile_id))
        # Check for no change
        elif request.form.get("username") == user_info[0]["username"] and request.form.get("email") == user_info[0]["email"]:
            flash("Profile remains unchanged.", category="message")
            return redirect(url_for("profile_username_email", profile_id=profile_id))
        
        # all good then change
        c.execute('''UPDATE all_users SET 
                    username = ?, email = ?
                        WHERE id = ? ''',
                    (request.form.get("username"), request.form.get("email"), session["user_id"]))

        flash("Profile updated.", category="message")
        return redirect(url_for("profile_username_email", profile_id=session["user_id"]))
    
    else:
        return render_template("profile.html", user_info=user_info, user_name=user_info)


# Displays all tasks tables
@app.route("/all_tasks_tables")
@login_required
def all_tasks():
    c = setup_connection()

    c.execute("SELECT username FROM all_users WHERE id = ?", (session["user_id"], ))
    user_name = c.fetchall()

    c.execute('''SELECT * FROM all_tables WHERE admin = ? AND dayweek = ?''', 
                (session["user_id"], 1))
    all_tasks_tables = c.fetchall()
    all_count = len(all_tasks_tables)

    return render_template("all_tasks_tables.html", all_tasks_tables=all_tasks_tables, all_count=all_count, user_name=user_name)


# Create new tasks table
@app.route("/new_tasks_table", methods=["POST"])
@login_required
def new_tasks_table():
    c = setup_connection()

    c.execute("SELECT username FROM all_users WHERE id = ?", (session["user_id"], ))
    user_name = c.fetchall()

    if request.method == "POST":
        # First check if same table name exists in the User's db
        c.execute(''' SELECT table_id FROM all_tables WHERE 
                    table_name = ? AND admin = ? AND dayweek = ?''', 
                    (request.form.get("tab_name"), session["user_id"], 1))
        table_exists = c.fetchall()            
        if len(table_exists) != 0:
            flash("You already have a tasks table with same name.", category="message")
            return redirect("/all_tasks_tables")

        # If all good, then generate passcode
        passcode = pass_code_unique()

        c.execute(''' INSERT INTO all_tables (admin, member_count, table_name, dayweek, passcode)
                    VALUES(?, ?, ?, ?, ?) ''', 
                    (session["user_id"], 1, request.form.get("tab_name"), 1, passcode))
        
        # Redirect to the table page
        c.execute(''' SELECT table_id FROM all_tables 
                    WHERE table_name = ? AND admin = ? AND dayweek = ?''', 
                    (request.form.get("tab_name"), session["user_id"], 1))
        this_table_id = c.fetchall()            
            
        flash("New tasks table created.", category="message")
        return redirect(url_for("tasks_table", table_id=this_table_id[0]["table_id"]))    


# Display a tasks table
@app.route("/<int:table_id>/tasks_table")
@login_required
def tasks_table(table_id):
    c = setup_connection()

    c.execute("SELECT username FROM all_users WHERE id = ?", (session["user_id"], ))
    user_name = c.fetchall()

    # Stop users from entering unauthorized tasks tables
    c.execute(''' SELECT table_id FROM all_tables WHERE admin = ? AND dayweek=?''',
                (session["user_id"], 1)) 
    all_tasks_table_id = c.fetchall()

    check = 0
    
    for i in range(len(all_tasks_table_id)):   
        if int(table_id) == all_tasks_table_id[i]["table_id"]:
            check = 1
            break
    if check == 0:
        return apology("Not your table..!", 403)  
    
    #--------------------------------------------------------
    c.execute(''' SELECT * FROM all_tables WHERE 
                table_id = ? ''', (table_id, ))
    table_info = c.fetchall()
    
    column_names = ['date', 'time', 'task']
    column = ['Date', 'Time', 'Task']

    c.execute(''' SELECT * FROM tasks_table WHERE
                    table_id = ?''', (table_id, ))
    this_tasks_table = c.fetchall()

    count_tasks = len(this_tasks_table)    
    
    return render_template("tasks_table.html", this_tasks_table=this_tasks_table, table_info=table_info, user_name=user_name, count_tasks=count_tasks, column_names=column_names, column=column)


# Handles adding a new task to a tasks table
@app.route("/<int:table_id>/add_task", methods=["POST"])
@login_required
def add_task(table_id):
    c = setup_connection()

    if request.method == "POST":
        c.execute(''' SELECT * FROM all_tables WHERE 
                table_id = ? ''', (table_id, ))
        table_info = c.fetchall()

        
        min = int(request.form.get("task_remind_min"))
        task_remind =  datetime.strptime(request.form.get("time"), "%H:%M") - timedelta(minutes = min)
        task_remind_time = task_remind.strftime("%H:%M")
        
        if table_info[0]["admin"] == session["user_id"]:
            c.execute('''INSERT INTO tasks_table
                    (table_id, date, time, task, task_remind_time)
                    VALUES(?, ? ,?, ?, ?)''',
                    (table_id, request.form.get("date"), request.form.get("time"), 
                    request.form.get("task"), task_remind_time))

            flash("New task added.", category="message")
            return redirect(url_for("tasks_table", table_id=table_info[0]["table_id"]))
        else:
            return apology("You aren't the table's admin..!", 403)
    

# Handles editing a task of a tasks table
@app.route("/<int:task_id>/edit_task", methods=["POST"])
@login_required
def edit_task(task_id):
    c = setup_connection() 

    if request.method == "POST":   
        c.execute(''' SELECT * FROM all_tables WHERE table_id IN
                    (SELECT table_id FROM tasks_table WHERE 
                    task_id = ?) ''', (task_id, ))
        table_info = c.fetchall()

        min = int(request.form.get("task_remind_min"))
        task_remind =  datetime.strptime(request.form.get("time"), "%H:%M") - timedelta(minutes = min)
        task_remind_time = task_remind.strftime("%H:%M")

        if table_info[0]["admin"] == session["user_id"]:
            c.execute('''UPDATE tasks_table SET
                        date=?, time=?, task=?, task_remind_time=?
                        WHERE task_id=?''',
                    (request.form.get("date"), request.form.get("time"), 
                    request.form.get("task"), task_remind_time, task_id))

            flash("Tasks Table updated.")
            return redirect(url_for("tasks_table", table_id=table_info[0]["table_id"]))
    else:
        return apology("You aren't the table's admin..!", 403)


# Handles deleting a task of tasks table
@app.route("/<int:task_id>/delete_task")
@login_required
def delete_task(task_id):
    c = setup_connection() 
     
    # Check for unauthorized task deletions
    c.execute(''' SELECT task_id FROM tasks_table WHERE table_id IN(
                SELECT table_id FROM all_tables WHERE admin = ? AND dayweek=?)''',
                (session["user_id"], 1)) 
    all_task_id = c.fetchall()

    check = 0
    for i in range(len(all_task_id)):   
        if int(task_id) == all_task_id[i]["task_id"]:
            check = 1
            break
    if check == 0:
        return apology("Not your table..!", 403)

    # If all good then delete task  
    else:
        c.execute(''' SELECT * FROM all_tables WHERE table_id IN(
                    SELECT table_id FROM tasks_table WHERE 
                    task_id = ?) ''', (task_id, ))
        table_info = c.fetchall()

        c.execute(''' DELETE FROM tasks_table WHERE 
                    task_id = ? ''', (task_id, ))

        flash("Task deleted.", category="message")
        return redirect(url_for("tasks_table", table_id=table_info[0]["table_id"]))               


# Delete a tasks table
@app.route("/<int:table_id>/delete_tasks_table")
@login_required
def delete_tasks_table(table_id):
    c = setup_connection()   

    # Check for unauthorized access
    c.execute(''' SELECT table_id FROM all_tables WHERE admin = ? AND dayweek=?''',
                (session["user_id"], 1)) 
    all_admin_tasks_table_id = c.fetchall()

    check = 0
    for i in range(len(all_admin_tasks_table_id)):   
        if int(table_id) == all_admin_tasks_table_id[i]["table_id"]:
            check = 1
            break
    if check == 0:
        return apology("Not your table..!", 403)
    
    # All good then delete
    else:
        c.execute(''' DELETE FROM tasks_table WHERE table_id = ? ''', (table_id, ))

        c.execute(''' DELETE FROM all_tables WHERE table_id = ? ''', (table_id, ))

        flash("Tasks table deleted", category="message")
        return redirect("/all_tasks_tables")

# Calling the reminder check function to start it's thread 
check_reminders()
