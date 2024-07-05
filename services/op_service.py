from flask import Flask, session
def do_login(user, CURR_USER_KEY):
    session[CURR_USER_KEY] = user.id

def do_logout(CURR_USER_KEY):
    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]

