class ExpectMap:
    def __init__(self, expected: dict[str, int]) -> None:
        self._expected: dict[str, int] = expected

    def received(self, name: str) -> None:
        self._expected[name] -= 1

    def get_expected(self) -> dict[str, int]:
        return self._expected

    def remaining(self) -> dict[str, int]:
        remaining = {}

        for name in self._expected:
            if self._expected[name] != 0:
                remaining[name] = self._expected[name]

        return remaining

    def done(self) -> bool:
        return len(self.remaining()) == 0
