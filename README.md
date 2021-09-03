YT Link for video presentation:
https://youtu.be/KUMUhMVcOM0

This project was the final project of CS50x course by HarvardX (Prof. David J. Malan) which I completed.

Project: 'Schedge'
It is a flask full stack web application that is basically a scheduler, with email alerts and tables with multiple participants (RDBMS).

Backend Language: Python (Flask)
Structure/ Style Tools: HTML5, CSS3 (Bootstrap 4)
Frontend Language: JavaScript, Jinja Template language

Features:
1. Week Tables: 
User can create week long schedules(5, 6 and 7 day- week) with multiple participants who can see the table, get alerts for each reminder/work but cannot change it. Only the admin of the table can add, edit and delete rows and add participants to that table. 

    1a. Add Participants: Either the admin of the table can add a participant that is registered with Schedge to the table or the aspirant can enter a unique 6-character randomly generated passcode to access the table.

    1b. So a user can create as well as subscribe to a particular week table and get alerts; either on time or 15, 30 minutes or 1 hour before it.

    1c. Also, users can unsubscribe from a particular table and will not receive any updates further.

2. Task Tables:
User can create personal task tables(multiple) and get alerts for each task from any table; either on time or 15, 30 minutes or 1 hour before it.

    2a. User can add, edit and delete tasks. Also, delete the whole table.

3. My Day:
This page will gather all tasks that are due today and display on the home page for quick reference.

    3a. Add task in any tasks table, if it is due today then it will show up here.

4. Change username and alert email:
User can change their unique username and email at any time

    4a. Passwords are saved and matched using hash functions from the werkzeug.security module.

    4b. Emails are sent using flask_mail module.
