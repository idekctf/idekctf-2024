from sqlalchemy.orm import Session, DeclarativeBase, relationship, Mapped
import os
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, select

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'users'
    id: int = Column(Integer, primary_key=True)
    username: str = Column(String)
    password: str = Column(String)

class Problem(Base):
    __tablename__ = 'problems'
    id: str = Column(String, primary_key=True)
    title: str = Column(String)
    description: str = Column(String)
    difficulty: int = Column(Integer)

class ProblemTestCase(Base):
    __tablename__ = 'problem_test_cases'
    id: int = Column(Integer, primary_key=True)
    problem_id: str = Column(String, ForeignKey('problems.id'))
    input: str = Column(String)
    output: str = Column(String)
    hidden: bool = Column(Integer)

class Submission(Base):
    __tablename__ = 'submissions'
    id: int = Column(Integer, primary_key=True)
    problem_id: str = Column(String, ForeignKey('problems.id'))
    user_id: int = Column(Integer, ForeignKey('users.id'))
    code: str = Column(String)
    status: str = Column(String)

    user: Mapped[User] = relationship('User', backref='submissions')
    problem: Mapped[Problem] = relationship('Problem', backref='submissions')

class SubmissionOutput(Base):
    __tablename__ = 'submission_outputs'
    id: int = Column(Integer, primary_key=True)
    submission_id: int = Column(Integer, ForeignKey('submissions.id'))
    testcase_id: int = Column(Integer, ForeignKey('problem_test_cases.id'))
    expected_output: str = Column(String)
    actual_output: str = Column(String)
    status: str = Column(String)

engine = create_engine('sqlite:///db.sqlite')
Base.metadata.create_all(engine)

with Session(engine) as db:
    flag = os.environ.get("FLAG")
    if flag:
        flag_case = db.scalar(select(ProblemTestCase).filter_by(problem_id="helloinput", hidden=True))
        # flag_case.input = flag
        flag_case.output = flag + "\n"
        db.commit()