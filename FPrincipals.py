# Todo: http://flask.pocoo.org/snippets/62/

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

# import flask_debugtoolbar

app = Flask(__name__)

app.config.update(
    # DEBUG_TB_INTERCEPT_REDIRECTS=False,
    # DEBUG_TB_TEMPLATE_EDITOR_ENABLED=True,
    DEBUG=True,
    SECRET_KEY='secret_xxx')

# flask_debugtoolbar.DebugToolbarExtension(app)

principals = Principal(app, skip_static=True)

be_editor = RoleNeed('editor')
to_sign_in = ActionNeed('sign_in')
sign_in = Permission(to_sign_in, be_editor)
sign_in.description = "Editor's permissions"


be_admin = RoleNeed('admin')
admin = Permission(be_admin)
admin.description = "Admin's permissions"

perms = [sign_in, admin]


@app.route('/')
@sign_in.require(http_exception=403)
def index():
    return render_template('index.html')


@app.route('/admin')
@admin.require(http_exception=403)
def admin():
    return render_template('admin.html')


@app.route('/privileges')
def privileges():
    return render_template('privileges.html')


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
    flash('This ressource is protected. You need more privileges.')
    priv = []
    for p in perms:
        priv.append(p.description)
        for n in p.needs:
            s = ('Method : {method}, value : {value}, provide : {provides}'
                 ).format(method=n.method,
                          value=n.value,
                          provides=(n in g.identity.provides))
            priv.append(s)

    return render_template('privileges.html', priv=priv)


@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    if identity.name != 'anon':
        identity.provides.add(to_sign_in)


if __name__ == "__main__":
    app.run()
