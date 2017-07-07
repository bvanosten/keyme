import unittest

from mock import patch
from keyme import writer


class TestWriter(unittest.TestCase):
    """Test suite for the writer module"""

    @patch('builtins.open')
    @patch('os.path.exists')
    @patch('keyme.writer.create_backup')
    @patch('keyme.writer.ConfigParser.write')
    @patch('keyme.writer.ConfigParser.read')
    def test_write_credentials_file(
            self,
            read,
            write,
            create_backup,
            exists,
            builtins_open
    ):
        """Should write a credentials file with the specified info"""

        exists.return_value = True

        result = writer.write_credentials_file(
            profile_name='TEST',
            access_key='ACCESS_KEY',
            secret_key='SECRET_KEY',
            session_token='SESSION_TOKEN'
        )

        self.assertEqual(1, read.call_count)
        self.assertEqual(1, write.call_count)
        self.assertEqual(1, create_backup.call_count)
        self.assertIn('TEST', result)

    @patch('builtins.open')
    @patch('os.path.exists')
    @patch('keyme.writer.create_backup')
    @patch('keyme.writer.ConfigParser.write')
    @patch('keyme.writer.ConfigParser.read')
    def test_write_config_file(
            self,
            read,
            write,
            create_backup,
            exists,
            builtins_open
    ):
        """Should write a config file with the specified info"""

        exists.return_value = True

        result = writer.write_config_file(profile_name='TEST')

        self.assertEqual(1, read.call_count)
        self.assertEqual(1, write.call_count)
        self.assertEqual(1, create_backup.call_count)
        self.assertIn('profile TEST', result)

    @patch('shutil.copy2')
    @patch('os.remove')
    @patch('os.path.exists')
    def test_create_backup(self, exists, remove, copy):
        """Should create a backup copy of the specified file"""

        exists.return_value = True

        path = 'fake'
        backup_path = 'fake.keyme.backup'
        result = writer.create_backup(path)
        self.assertTrue(result)
        self.assertEqual(1, remove.call_count)
        self.assertEqual(remove.call_args[0][0], backup_path)
        self.assertEqual(1, copy.call_count)
        self.assertEqual(copy.call_args[0][0], path)
        self.assertEqual(copy.call_args[0][1], backup_path)

    @patch('os.path.exists')
    def test_create_backup_error(self, exists):
        """Should fail to create a backup copy of the specified file"""

        exists.side_effect = IOError('FAKE')

        result = writer.create_backup('fake-path')
        self.assertFalse(result)
