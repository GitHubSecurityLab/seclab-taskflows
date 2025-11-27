# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

from sqlalchemy import String, Text, Integer, ForeignKey, Column
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped, relationship
from typing import Optional

class Base(DeclarativeBase):
    pass


class Source(Base):
    __tablename__ = 'source'

    id: Mapped[int] = mapped_column(primary_key=True)
    repo: Mapped[str]
    source_location: Mapped[str]
    type: Mapped[str]
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self):
        return (f"<Source(id={self.id}, repo={self.repo}, "
                f"location={self.source_location}, type={self.type}, "
                # f"line={self.line},",
                f"notes={self.notes})>")
