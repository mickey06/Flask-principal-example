# -*- coding: utf-8 -*-

from flask import (
    abort,
    flash,
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for)

from flask_principal import (
    ActionNeed,
    AnonymousIdentity,
    Identity,
    identity_changed,
    identity_loaded,
    Permission,
    Principal,
    RoleNeed)


app = Flask(__name__)

app.config.update(
    DEBUG=True,
    SECRET_KEY='secret_xxx')


principals = Principal(app, skip_static=True)

# Needs
be_admin = RoleNeed('admin')
be_editor = RoleNeed('editor')
to_sign_in = ActionNeed('sign in')

# Permissions
user = Permission(to_sign_in)
user.description = "User's permissions"
editor = Permission(to_sign_in, be_editor)
editor.description = "Editor's permissions"
admin = Permission(to_sign_in, be_admin)
admin.description = "Admin's permissions"

apps_needs = [be_admin, be_editor, to_sign_in]
apps_permissions = [user, editor, admin]


@app.route('/')
@user.require(http_exception=403)
def index():
    return render_template('index.html')


@app.route('/admin')
@admin.require(http_exception=403)
def admin():
    return render_template('admin.html')


def current_privileges():
    return (('{method} : {value}').format(method=n.method, value=n.value)
            for n in apps_needs if n in g.identity.provides)


@app.route('/privileges')
def privileges():
    flash(('Your current identity is {id}.').format(id=g.identity.name))

    return render_template('privileges.html', priv=current_privileges())


def authenticate(email, password):
    if password == email + "_":
        return "my_only_user"
    else:
        return None


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = authenticate(request.form['email'],
                               request.form['password'])
        if user_id:
            identity = Identity(user_id)
            identity_changed.send(app, identity=identity)
            return redirect(url_for('index'))
        else:
            return abort(401)
    return render_template('login.html')


@app.route("/logout")
def logout():
    for key in ['identity.name', 'identity.auth_type']:
        session.pop(key, None)
    identity_changed.send(app, identity=AnonymousIdentity())
    return render_template('logout.html')


@app.errorhandler(401)
def authentication_failed(e):
    flash('Authenticated failed.')
    return redirect(url_for('login'))


@app.errorhandler(403)
def authorisation_failed(e):
    return privileges()


@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    if identity.name != 'anon':
        identity.provides.add(to_sign_in)


if __name__ == "__main__":
    app.run()
