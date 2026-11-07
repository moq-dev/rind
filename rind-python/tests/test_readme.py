"""The README's example runs as written."""

import pathlib
import re
import unittest

README = pathlib.Path(__file__).resolve().parents[1] / "README.md"


class Readme(unittest.TestCase):
    def test_example_runs(self):
        blocks = re.findall(r"```python\n(.*?)```", README.read_text(), re.S)
        self.assertTrue(blocks)
        for block in blocks:
            exec(compile(block, str(README), "exec"), {})


if __name__ == "__main__":
    unittest.main()
