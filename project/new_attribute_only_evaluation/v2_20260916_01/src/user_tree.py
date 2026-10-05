from __future__ import annotations


class UserTree:
    def __init__(self, users: int):
        if users < 1 or users & (users - 1):
            raise ValueError("users must be a positive power of two")
        self.users = users

    def path(self, uid: int) -> tuple[int, ...]:
        if not 0 <= uid < self.users:
            raise KeyError(uid)
        node = self.users + uid
        result = []
        while node:
            result.append(node)
            node //= 2
        return tuple(result)

    def cover(self, revoked: set[int]) -> frozenset[int]:
        if any(uid < 0 or uid >= self.users for uid in revoked):
            raise KeyError("unknown revoked uid")

        def walk(node: int, lo: int, hi: int) -> set[int]:
            if not any(lo <= uid < hi for uid in revoked):
                return {node}
            if hi - lo == 1:
                return set()
            middle = (lo + hi) // 2
            return walk(node * 2, lo, middle) | walk(node * 2 + 1, middle, hi)

        return frozenset(walk(1, 0, self.users))

    def matching(self, uid: int, cover: frozenset[int]) -> int | None:
        return next((node for node in self.path(uid) if node in cover), None)
