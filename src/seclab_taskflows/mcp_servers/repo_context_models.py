# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

from sqlalchemy import String, Text, Integer, ForeignKey, Column
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped, relationship
from typing import Optional

class Base(DeclarativeBase):
    pass

class Application(Base):
    __tablename__ = 'application'

    id: Mapped[int] = mapped_column(primary_key=True)
    repo: Mapped[str]
    location: Mapped[str]
    notes: Mapped[str] = mapped_column(Text)
    is_app: Mapped[bool] = mapped_column(nullable=True)
    is_library: Mapped[bool] = mapped_column(nullable = True)

    def __repr__(self):
        return (f"<Application(id={self.id}, repo={self.repo}, "
                f"location={self.location}, is_app={self.is_app}, is_library={self.is_library}"
                f"notes={self.notes}>")

class ApplicationIssue(Base):
    __tablename__ = 'application_issue'
    id: Mapped[int] = mapped_column(primary_key=True)
    repo: Mapped[str]
    component_id = Column(Integer, ForeignKey('application.id', ondelete='CASCADE'))
    issue_type: Mapped[str] = mapped_column(Text)
    notes: Mapped[str] = mapped_column(Text)

    def __repr__(self):
        return (f"<ApplicationIssue(id={self.id}, repo={self.repo}, "
                f"component_id={self.component_id}, issue_type={self.issue_type}, notes={self.notes})>")

class AuditResult(Base):
    __tablename__ = 'audit_result'
    id: Mapped[int] = mapped_column(primary_key = True)
    repo: Mapped[str]
    component_id = Column(Integer, ForeignKey('application.id', ondelete = 'CASCADE'))
    issue_type: Mapped[str] = mapped_column(Text)
    issue_id = Column(Integer, ForeignKey('application_issue.id', ondelete = 'CASCADE'))
    has_vulnerability: Mapped[bool]
    has_non_security_error: Mapped[bool]
    notes: Mapped[str] = mapped_column(Text)

    def __repr__(self):
        return (f"<AuditResult(id={self.id}, repo={self.repo}, has_vulnerability={self.has_vulnerability}, has_non_security_error={self.has_non_security_error}, "
                f"component_id={self.component_id}, issue_type={self.issue_type}, issue_id={self.issue_id}, notes={self.notes})>")

class EntryPoint(Base):
    __tablename__ = 'entry_point'

    id: Mapped[int] = mapped_column(primary_key=True)
    app_id = Column(Integer, ForeignKey('application.id', ondelete='CASCADE'))
    file: Mapped[str]
    user_input: Mapped[str]
    line: Mapped[int]
    notes: Mapped[str] = mapped_column(Text)
    repo: Mapped[str]

    def __repr__(self):
        return (f"<EntryPoint(app_id={self.app_id}, file={self.file}, user_input={self.user_input}, "
                f"lines={self.lines}, notes={self.notes})>")
    
class WebEntryPoint(Base): # an entrypoint of a web application (such as GET /info) with additional properties
    __tablename__ = 'web_entry_point'

    id: Mapped[int] = mapped_column(primary_key=True)
    entry_point_id = Column(Integer, ForeignKey('entry_point.id', ondelete='CASCADE'))
    method: Mapped[str] # GET, POST, etc
    path: Mapped[str] # /info
    component: Mapped[int]
    auth: Mapped[str]
    middleware: Mapped[str]
    roles_scopes: Mapped[str]
    notes: Mapped[str] = mapped_column(Text)
    repo: Mapped[str]

    def __repr__(self):
        return (f"<WebEntryPoint(entry_point_id={self.entry_point_id}, "
                f"method={self.method}, path={self.path}, component={self.component}, "
                f"auth={self.auth}, middleware={self.middleware}, roles_scopes={self.roles_scopes}, "
                f"notes={self.notes}, repo={self.repo})>")

class UserAction(Base):
    __tablename__ = 'user_action'

    id: Mapped[int] = mapped_column(primary_key=True)
    repo: Mapped[str]
    app_id = Column(Integer, ForeignKey('application.id', ondelete='CASCADE'))
    file: Mapped[str]
    line: Mapped[int]
    notes: Mapped[str] = mapped_column(Text)
