import ast, json, os, pathlib, tempfile, unittest
class PrivateFilesTest(unittest.TestCase):
    def test_credentials_are_private_and_replace_symlink(self):
        tree = ast.parse(pathlib.Path(__file__).with_name('gtc.py').read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'save_store')
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = root / 'config'
            config.mkdir()
            target = root / 'outside'
            target.write_text('untouched')
            credential = config / 'credentials.json'
            credential.symlink_to(target)
            scope = dict(CONFIG_DIR=config, CRED_FILE=credential, Path=pathlib.Path, tempfile=tempfile, json=json, os=os)
            exec(compile(ast.Module(body=[function], type_ignores=[]), 'save_store', 'exec'), scope)
            scope['save_store']({'token': 'fixture-not-a-real-token'})
            self.assertEqual(target.read_text(), 'untouched')
            self.assertFalse(credential.is_symlink())
            self.assertEqual(credential.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(credential.read_text())['token'], 'fixture-not-a-real-token')
if __name__ == '__main__': unittest.main()
