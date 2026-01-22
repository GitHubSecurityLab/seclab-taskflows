# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

from sqlalchemy import Text
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped
from typing import Optional

class Base(DeclarativeBase):
    pass


class Source(Base):
    __tablename__ = 'source'

    id: Mapped[int] = mapped_column(primary_key=True)
    repo: Mapped[str]
    source_location: Mapped[str]
    line: Mapped[int]
    source_type: Mapped[str]
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self):
        return (f"<Source(id={self.id}, repo={self.repo}, "
                f"location={self.source_location}, line={self.line}, source_type={self.source_type}, "
                f"notes={self.notes})>")
