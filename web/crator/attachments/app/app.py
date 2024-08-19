from functools import wraps
import shutil
import subprocess
import sys
import time
from flask import *
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from db import *

app = Flask(__name__)
app.secret_key = 'very very very sekret key'

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login?next=' + request.path)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def problems_list():
    with Session(engine) as db:
        problems = db.scalars(select(Problem)).all()
    return render_template('index.html', problems=problems)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    # Create user
    username = request.form['username']
    password = request.form['password']
    with Session(engine) as db:
        if db.execute(select(User).filter_by(username=username)).scalar():
            return render_template('register.html', message='Username already taken')
        db.add(User(username=username, password=password))
        db.commit()
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    # Get form fields
    username = request.form['username']
    password = request.form['password']
    next = request.args.get('next', '/')
    # Check user
    with Session(engine) as db:
        user = db.scalar(select(User).filter_by(username=username, password=password))
    if user is None:
        return render_template('login.html', message='Invalid username or password')
    session['user_id'] = user.id
    session['username'] = user.username
    return redirect(next)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect('/')

@app.route('/problem/<problem_id>')
def problem(problem_id):
    with Session(engine) as db:
        problem = db.scalar(select(Problem).filter_by(id=problem_id))
    if not problem:
        abort(404)
    return render_template('problem.html', problem=problem)

def __cleanup_test_case(submission_id):
    os.remove(f'/tmp/{submission_id}.in')
    os.remove(f'/tmp/{submission_id}.out')
    os.remove(f'/tmp/{submission_id}.expected')

@app.route('/submit/<problem_id>', methods=['GET', 'POST'])
@login_required
def submit(problem_id):
    with Session(engine) as db:
        # Select problem
        problem = db.scalar(select(Problem).filter_by(id=problem_id))
        if not problem:
            abort(404)
        if request.method == 'GET':
            return render_template('submit.html', problem=problem)
        
        # Get testcases, code, sandbox
        testcases = db.scalars(select(ProblemTestCase).filter_by(problem_id=problem_id)).all()
        code = request.form['code']
        if len(code) > 32768:
            return abort(400)
        with open('sandbox.py', 'r') as f:
            sandbox = f.read()

        # Create submission
        submission = Submission(problem_id=problem_id, user_id=session['user_id'], code=code, status='Pending')
        db.add(submission)
        db.commit()
        submission_id = submission.id

        # Prepare code
        shutil.copy('sandbox.py', f'/tmp/sandbox.py')
        with open(f'/tmp/{submission_id}.py', 'w') as f:
            f.write(f'__import__("sandbox").Sandbox("{submission_id}")\n' + code.replace('\r\n', '\n'))
        
        # Run testcases
        skip_remaining_cases = False
        for testcase in testcases:
            # Set testcase staus
            submission_case = SubmissionOutput(submission_id=submission_id, testcase_id=testcase.id, status='Pending')
            db.add(submission_case)
            if skip_remaining_cases:
                submission_case.status = 'Skipped'
                db.commit()
                continue

            if not testcase.hidden:
                submission_case.expected_output = testcase.output
            # Set up input and output files
            with open(f'/tmp/{submission_id}.in', 'w') as f:
                f.write(testcase.input.replace('\r\n', '\n'))
            with open(f'/tmp/{submission_id}.expected', 'w') as f:
                f.write(testcase.output.replace('\r\n', '\n'))

            # Run code
            try:
                proc = subprocess.run(f'sudo -u nobody -g nogroup python3 /tmp/{submission_id}.py < /tmp/{submission_id}.in > /tmp/{submission_id}.out', shell=True, timeout=1)
                if proc.returncode != 0:
                    submission.status = 'Runtime Error'
                    skip_remaining_cases = True
                    submission_case.status = 'Runtime Error'
                else:
                    diff = subprocess.run(f'diff /tmp/{submission_id}.out /tmp/{submission_id}.expected', shell=True, capture_output=True)
                    if diff.stdout:
                        submission.status = 'Wrong Answer'
                        skip_remaining_cases = True
                        submission_case.status = 'Wrong Answer'
                    else:
                        submission_case.status = 'Accepted'
            except subprocess.TimeoutExpired:
                submission.status = 'Time Limit Exceeded'
                skip_remaining_cases = True
                submission_case.status = 'Time Limit Exceeded'
            
            # Cleanup
            with open(f'/tmp/{submission_id}.out', 'r') as f:
                submission_case.actual_output = f.read(1024)
            db.commit()
            __cleanup_test_case(submission_id)
        # Set overall status
        if submission.status == 'Pending':
            submission.status = 'Accepted'
            db.commit()
        os.remove(f'/tmp/{submission_id}.py')
        return redirect(f'/submission/{submission_id}')

@app.route('/submission/<submission_id>')
@login_required
def submission(submission_id):
    # Find matching submission for user
    with Session(engine) as db:
        submission = db.scalar(select(Submission).filter_by(id=submission_id).options(joinedload(Submission.problem)))
        if not submission:
            abort(404)
        if submission.user_id != session['user_id']:
            abort(403)
        # Get testcases
        testcases = db.scalars(select(SubmissionOutput).filter_by(submission_id=submission_id)).all()
    return render_template('submission.html', submission=submission, testcases=testcases)

@app.route('/submissions')
def submissions():
    with Session(engine) as db:
        submissions = db.scalars(select(Submission).options(joinedload(Submission.user))).all()
    return render_template('submissions.html', submissions=submissions)

@app.errorhandler(400)
def handler_400(e):
    return 'What do you think you\'re doing?', 400

@app.errorhandler(403)
def handler_403(e):
    return 'Who do you think you are?', 403

@app.errorhandler(404)
def handler_404(e):
    return 'Where do you think you\'re going?', 404

@app.errorhandler(405)
def handler_405(e):
    return 'Why do you think you can do this?', 405

@app.errorhandler(418)
def handler_418(e):
    return 'I\'m a ' + os.environ.get("F1ag"), 418
    # :)

@app.errorhandler(500)
def handler_500(e):
    import traceback
    print(traceback.format_exception(e))
    sys.exit(1)
    # No hacking :)