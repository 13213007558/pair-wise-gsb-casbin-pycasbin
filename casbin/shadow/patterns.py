# Copyright 2026 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Resource path patterns for the shadow checker.

A pattern is a '/'-separated sequence of segments where each segment is
either a literal or the single-segment wildcard ``*``, optionally followed
by a trailing ``**`` segment that matches zero or more further segments.

Semantics (deliberately stricter than keyMatch2):

- ``*``  matches exactly one path segment, never ``/``.
- ``**`` is only allowed as the last segment and matches zero or more
  complete segments, so ``/a/**`` matches ``/a``, ``/a/b`` and ``/a/b/c``.
- ``/a/*`` matches ``/a/x`` but NOT ``/a/x/y``.

The module implements intersection, the coverage (subset) test and a
witness-producing emptiness check for the difference between one pattern
and the union of a set of patterns.  The difference itself is not
representable in this pattern language (e.g. ``/*`` minus ``/a``), so
coverage is decided by a direct search for a counter-example path instead
of by materialising the difference.
"""

STAR = "*"
DOUBLE_STAR = "**"


class PatternError(ValueError):
    """raised when a resource pattern is outside the supported language"""


def split_path(path):
    """splits a concrete path or pattern into segments, dropping empties."""
    return [seg for seg in str(path).split("/") if seg != ""]


class PathPattern:
    """a resource pattern: literal segments, '*' segments, optional trailing '**'."""

    __slots__ = ("segments", "tail", "leading")

    def __init__(self, segments, tail=False, leading=True):
        self.segments = tuple(segments)
        self.tail = bool(tail)
        # rendering style for generated witness paths, kept separate from
        # the matching semantics: "data1" vs "/data1".
        self.leading = bool(leading)

    @classmethod
    def parse(cls, text, allow_wildcards=True):
        """parses a pattern string such as '/a/*' or '/a/**'."""
        text = str(text)
        segments = split_path(text)
        tail = False
        fixed = []
        for i, seg in enumerate(segments):
            if seg == DOUBLE_STAR:
                if not allow_wildcards:
                    raise PatternError("wildcard '**' not supported by this matcher: %r" % text)
                if i != len(segments) - 1:
                    raise PatternError("'**' is only allowed as the last segment: %r" % text)
                tail = True
            elif seg == STAR:
                if not allow_wildcards:
                    raise PatternError("wildcard '*' not supported by this matcher: %r" % text)
                fixed.append(STAR)
            elif STAR in seg:
                raise PatternError("'*' must occupy a whole path segment: %r" % text)
            else:
                fixed.append(seg)
        return cls(fixed, tail, leading=text.startswith("/"))

    def _segment_at(self, index):
        """segment constraint at position, STAR beyond the fixed prefix if tailed."""
        if index < len(self.segments):
            return self.segments[index]
        if self.tail:
            return STAR
        return None

    def matches(self, path):
        """True if the concrete path string is matched by this pattern."""
        segments = split_path(path)
        if len(segments) < len(self.segments):
            return False
        if len(segments) > len(self.segments) and not self.tail:
            return False
        for i, seg in enumerate(segments):
            constraint = self._segment_at(i)
            if constraint is not None and constraint != STAR and constraint != seg:
                return False
        return True

    def intersect(self, other):
        """returns a pattern for the intersection, or None if disjoint."""
        if not self.tail and not other.tail and len(self.segments) != len(other.segments):
            return None
        if not self.tail and len(self.segments) < len(other.segments):
            return None
        if not other.tail and len(other.segments) < len(self.segments):
            return None
        if self.tail and other.tail:
            length = max(len(self.segments), len(other.segments))
        elif self.tail:
            length = len(other.segments)
        else:
            length = len(self.segments)
        merged = []
        for i in range(length):
            a = self._segment_at(i)
            b = other._segment_at(i)
            if a is None or b is None:
                return None
            if a == STAR:
                merged.append(b)
            elif b == STAR:
                merged.append(a)
            elif a == b:
                merged.append(a)
            else:
                return None
        return PathPattern(merged, self.tail and other.tail, leading=self.leading)

    def covers(self, other):
        """True if every path matched by ``other`` is also matched by ``self``."""
        if len(self.segments) > len(other.segments):
            return False
        if len(self.segments) < len(other.segments) and not self.tail:
            return False
        if other.tail and not self.tail:
            return False
        for i in range(len(other.segments)):
            constraint = self._segment_at(i)
            target = other.segments[i]
            if constraint == STAR:
                continue
            if constraint != target:
                return False
        return True

    def minimal_path(self):
        """returns one concrete path matched by this pattern."""
        return self.render(seg if seg != STAR else "x" for seg in self.segments)

    def render(self, segments):
        """renders concrete segments in this pattern's original path style."""
        joined = "/".join(segments)
        return "/" + joined if self.leading else joined

    def __eq__(self, other):
        return (
            isinstance(other, PathPattern)
            and self.segments == other.segments
            and self.tail == other.tail
        )

    def __hash__(self):
        return hash((self.segments, self.tail))

    def __repr__(self):
        parts = list(self.segments)
        if self.tail:
            parts.append(DOUBLE_STAR)
        return "PathPattern(/" + "/".join(parts) + ")"


def _fresh_literal(taken):
    """returns a literal not present in ``taken``."""
    candidate = "__shadow_probe__"
    while candidate in taken:
        candidate += "_"
    return candidate


def _witness_at_length(pattern, others, length):
    """one concrete path of exactly ``length`` segments matched by ``pattern``
    and by no pattern in ``others``, or None if every such path is covered."""
    if length < len(pattern.segments):
        return None
    if length > len(pattern.segments) and not pattern.tail:
        return None

    forced = []
    for i in range(length):
        constraint = pattern._segment_at(i)
        forced.append(constraint if constraint not in (None, STAR) else None)

    dangerous = []
    for other in others:
        if not other.tail and len(other.segments) != length:
            continue
        if other.tail and len(other.segments) > length:
            continue
        consistent = True
        for i, seg in enumerate(other.segments):
            if seg != STAR and forced[i] is not None and forced[i] != seg:
                consistent = False
                break
        if consistent:
            dangerous.append(other)

    if not dangerous:
        return pattern.render(seg if seg is not None else "x" for seg in forced)

    # each dangerous pattern must be avoidable on at least one free position
    for other in dangerous:
        avoidable = any(
            seg != STAR and forced[i] is None for i, seg in enumerate(other.segments)
        )
        if not avoidable:
            return None

    witness = list(forced)
    remaining = list(dangerous)
    for i in range(length):
        if not remaining:
            break
        if witness[i] is not None:
            continue
        taken = {other.segments[i] for other in remaining if other.segments[i] != STAR}
        if not taken:
            continue
        witness[i] = _fresh_literal(taken)
        remaining = [other for other in remaining if other.segments[i] == STAR]

    if remaining:
        return None
    return pattern.render(seg if seg is not None else "x" for seg in witness)


def find_path_outside(pattern, others):
    """decides whether ``pattern`` is fully covered by the union of ``others``.

    Returns None when every path matched by ``pattern`` is matched by at
    least one pattern in ``others``; otherwise returns a concrete witness
    path matched by ``pattern`` and by none of ``others``.
    """
    others = [other for other in others if pattern.intersect(other) is not None]
    if not others:
        return pattern.minimal_path()
    for other in others:
        if other.covers(pattern):
            return None

    max_length = max(len(other.segments) for other in others)
    max_length = max(max_length, len(pattern.segments))
    if pattern.tail:
        # one extra length: beyond every opponent's fixed prefix only tailed
        # opponents remain dangerous, and longer lengths behave identically.
        max_length += 1
    for length in range(len(pattern.segments), max_length + 1):
        witness = _witness_at_length(pattern, others, length)
        if witness is not None:
            return witness
    return None
