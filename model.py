from sqlalchemy import create_engine, Column, String, Integer, ForeignKey, DATETIME
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import json

Base = declarative_base()

class CVE(Base):
    __tablename__ = 'cve'

    id = Column(Integer, primary_key=True)
    cve_id = Column(String)
    description = Column(String)
    vulnerability = Column(String)
    severity = Column(String)
    category = Column(String)
    solutions = Column(String)
    scan_id = Column(Integer, ForeignKey('scan.scan_id'))

    scan = relationship("Scan", back_populates="cves")


class Solution(Base):
    __tablename__ = 'solution'

    id = Column(Integer, primary_key=True)
    file = Column(String)
    comments = Column(String)
    timestamp = Column(DATETIME)
    scan_id = Column(Integer, ForeignKey('scan.scan_id'))

    scan = relationship("Scan", back_populates="solution")


class Scan(Base):
    __tablename__ = 'scan'

    id = Column(Integer, primary_key=True)
    scan_id = Column(String, unique=True)
    related_links = Column(String)  # Store as a comma-separated string
    tags = Column(String)  # Store as a comma-separated string
    timestamp = Column(DATETIME)
    pom = Column(String)
    project_id = Column(Integer, ForeignKey('project.project_id'))

    project = relationship("Project", back_populates="scans")
    cves = relationship("CVE", back_populates="scan", cascade="all, delete")
    solution = relationship("Solution", back_populates="scan", uselist=False, cascade="all, delete")


class Project(Base):
    __tablename__ = 'project'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    project_id = Column(String, unique=True)
    githublink = Column(String)

    scans = relationship("Scan", back_populates="project", cascade="all, delete")


# Create the database engine and session
engine = create_engine('sqlite:///projects.db')
Session = sessionmaker(bind=engine)

Base.metadata.create_all(engine)
