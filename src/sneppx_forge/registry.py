class ModelRegistry:
    """In-memory registry of signed model listings (skeleton)."""

    def __init__(self):
        self._models = {}
        self._next = 0

    def register(self, name, uri, signature=None):
        entry = {
            "id": self._next,
            "name": name,
            "uri": uri,
            "signature": signature,
            "verified": signature is not None,
        }
        self._models[name] = entry
        self._next += 1
        return entry

    def get(self, name):
        return self._models.get(name)

    def list(self):
        return list(self._models.values())
