import os.path as op
from flask import Flask, render_template
from peewee import * 
from flask_peewee.db import Database
import flask_admin as admin
from flask_admin.contrib.peewee import ModelView
from flask_admin.contrib.fileadmin import FileAdmin
from flask_security import Security, PeeweeUserDatastore, \
    UserMixin, RoleMixin, login_required, roles_required, \
    current_user

# Create app
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret'
app.config['DATABASE'] = {
    'name': 'data/DAS.db',
    'engine': 'peewee.SqliteDatabase',
}

# Create database connection object
db = Database(app)

class Role(db.Model, RoleMixin):
    name = CharField(unique=True)
    description = TextField(null=True)

class User(db.Model, UserMixin):
    username = CharField(max_length=80)
    email = CharField(max_length=120)
    password = TextField()
    active = BooleanField(default=True)
    confirmed_at = DateTimeField(null=True)
    
    def __unicode__(self):
        return self.username

class UserRoles(db.Model):
    # Because peewee does not come with built-in many-to-many
    # relationships, we need this intermediary class to link
    # user to roles.
    user = ForeignKeyField(User, related_name='roles')
    role = ForeignKeyField(Role, related_name='users')
    name = property(lambda self: self.role.name)
    description = property(lambda self: self.role.description)

class UserInfo(db.Model):
    key = CharField(max_length=64)
    value = CharField(max_length=64)
    user = ForeignKeyField(User)

    def __unicode__(self):
        return '%s - %s' % (self.key, self.value)
        
class RoleInfo(db.Model):
    key = CharField(max_length=64)
    value = CharField(max_length=64)
    Role = ForeignKeyField(Role)

    def __unicode__(self):
        return '%s - %s' % (self.key, self.value)
        
class UserRolesInfo(db.Model):
    key = CharField(max_length=64)
    value = CharField(max_length=64)
    UserRoles = ForeignKeyField(UserRoles)

    def __unicode__(self):
        return '%s - %s' % (self.key, self.value)

class Post(db.Model):
    title = CharField(max_length=120)
    text = TextField(null=False)
    date = DateTimeField()
    user = ForeignKeyField(User)

    def __unicode__(self):
        return self.title

class File(db.Model):
    title = TextField()
    author = TextField()
    edition = IntegerField()
    size = TextField()
    filename = TextField()
    file_type = TextField()
    created_at = DateTimeField()
    last_modified = DateTimeField()
    last_modified_by = ForeignKeyField(User)
    file_path = TextField()
    hidden = IntegerField()  

class UserAdmin(ModelView):
    inline_models = (UserInfo,)
    
class RoleAdmin(ModelView):
    inline_models = (RoleInfo,)
    
class UserRolesAdmin(ModelView):
    inline_models = (UserRolesInfo,)

class PostAdmin(ModelView):
    # Visible columns in the list view
    column_exclude_list = ['text']
    # List of columns that can be sorted. For 'user' column, use User.email as
    # a column.
    column_sortable_list = ('title', ('user', User.email), '')
    # Full text search
    column_searchable_list = ('title', User.username)
    # Column filters
    column_filters = ('title',
                      'date',
                      User.username)
    form_ajax_refs = {
        'user': {
            'fields': (User.username, 'email')
        }
    }
    
class FilesAdmin(ModelView):
    # Visible columns in the list view
    column_exclude_list = ['text']
    # List of columns that can be sorted. For 'user' column, use User.email as
    # a column.
    column_sortable_list = ('title', 'author', 'edition',
                            'size', 'filename', 'file_type',
                            'created_at','last_modified',
                            ('last_modified_by',User.email),
                            'file_path', 'hidden')

    # Full text search
    column_searchable_list = ('title', User.username)
    # Column filters
    column_filters = ('title', 'author', 'edition',
                        'size', 'filename', 'file_type',
                        User.username,)
    
# Setup Flask-Security
user_datastore = PeeweeUserDatastore(db, User, Role, UserRoles)
security = Security(app, user_datastore)


# Create a user to test with
@app.before_first_request
def create_user():
    for Model in (Role, User, UserRoles):
        Model.drop_table(fail_silently=True)
        Model.create_table(fail_silently=True)
    ADMIN = user_datastore.create_role(name='Admin', description='Full Access')        
    USER = user_datastore.create_user(username='hellrungj', email='hellrungj@berea.edu', password='Natioh22')
    user_datastore.add_role_to_user(USER,ADMIN)
# Views
@app.route('/')
@login_required
def home():
    return render_template('index.html', user = current_user, 
    role = user_datastore.find_role(current_user))
    
@app.route('/index')
@login_required
@roles_required('Admin')
def index():
    return "Got in!"
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
    form = LoginForm()
    if form.validate_on_submit():
        # Login and validate the user.
        # user should be an instance of your `User` class
        login_user(user)

        Flask.flash('Logged in successfully.')

        next = Flask.request.args.get('next')
        # next_is_valid should check if the user has valid
        # permission to access the `next` url
        if not next_is_valid(next):
            return Flask.abort(400)

        return Flask.redirect(next or Flask.url_for('index'))
    return Flask.render_template('login.html', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(somewhere)

if __name__ == '__main__':
    import logging
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)

    admin = admin.Admin(app, name='DAS Admin')
    
    path = op.join(op.dirname(__file__), 'static')
    
    admin.add_view(FileAdmin(path, '/static/', name='Static File'))
    admin.add_view(UserAdmin(User))
    admin.add_view(RoleAdmin(Role))
    admin.add_view(UserRolesAdmin(UserRoles))
    admin.add_view(PostAdmin(Post))
    admin.add_view(FilesAdmin(File))

    try:
        User.create_table()
        UserInfo.create_table()
        RoleInfo.create_table()
        UserRolesInfo.create_table()
        Post.create_table()
        File.create_table()
    except:
        pass

    app.run(host = '0.0.0.0',
    port = 8080,
    debug = True,
    threaded = True)