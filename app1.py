from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///D:\\code\\py\\database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.first_request_done = False
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

db = SQLAlchemy(app)

novels = [
    {'title': 'Novel 1', 'image': 'static/images/novel1.jpg', 'id': 1},
]

# 定义数据库模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    # 为了方便，我们添加一个设置密码的方法
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # 验证密码的方法
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
# 确保数据库和模型同步
with app.app_context():
    db.create_all()
    
# 创建数据库和表（如果它们还不存在的话）
@app.before_request
def before_first_request_func():
    if not app.first_request_done:
        app.first_request_done = True

# 用户加载函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 注册页面路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if not username or not email or not password:
            flash('请填写内容！')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('注册成功!')
        return redirect(url_for('login'))
    return render_template('register.html')

# 登录页面路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('请填写用户名和密码')
            return redirect(url_for('login'))
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('登录成功!')
            return redirect(url_for('index'))
        else:
            flash('密码错误或用户名错误')
            return redirect(url_for('login'))
    return render_template('login.html')

# 登出路由
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已登出！')
    return redirect(url_for('index'))

# 首页路由
@app.route('/')
def index():
    return render_template('index.html', novels=novels)

# 在模板中使用的上下文处理器来检查登录状态
@app.context_processor
def inject_login_status():
    return dict(is_logged_in=current_user.is_authenticated)

# 阅读界面路由
@app.route('/read/<int:novel_id>')
def read(novel_id):
    # 在实际应用中，这里应该根据novel_id从数据库中获取网文内容
    novel = next((n for n in novels if n['id'] == novel_id), None)
    if novel:
        return render_template('read.html', novel=novel)
    return 'Novel not found'

if __name__ == '__main__':
    app.run(debug=True)