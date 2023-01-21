import unittest

if __name__ == "__main__":
    test_suite = unittest.defaultTestLoader.discover("./test", pattern="test*.py")
    test_runner = unittest.TextTestRunner(verbosity=2)
    test_runner.run(test_suite)
