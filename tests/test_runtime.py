import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from iterm2_harness.common import APIError
from iterm2_harness.security import DEFAULT_CONFIG
from fakes import App, sdk_for

ROOT=Path(__file__).resolve().parents[1]


class RuntimeTests(unittest.TestCase):
    def test_import_has_no_server_or_config_side_effect(self):
        spec=importlib.util.spec_from_file_location('entrypoint',ROOT/'iterm2-harness.py')
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertTrue(callable(module.run))

    def test_package_works_through_external_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            link=Path(td)/'iterm2-harness.py'
            link.symlink_to(ROOT/'iterm2-harness.py')
            result=subprocess.run([sys.executable,str(link),'--version'],capture_output=True,text=True,check=True)
            self.assertEqual(result.stdout.strip(),'2.1.0')

    def test_copy_install_copies_package_not_just_launcher(self):
        with tempfile.TemporaryDirectory() as td:
            home=Path(td)
            target=home/'AutoLaunch'
            env=dict(os.environ, HOME=td, ITERM2_HARNESS_HOME=str(home/'state'))
            subprocess.run(['bash',str(ROOT/'install.sh'),'--copy','--target',str(target)],env=env,check=True,capture_output=True)
            launcher=target/'iterm2-harness.py'
            self.assertTrue(launcher.is_symlink())
            self.assertNotEqual(launcher.resolve().parent,ROOT)
            self.assertTrue((launcher.resolve().parent/'iterm2_harness/server.py').exists())
            result=subprocess.run([sys.executable,str(launcher),'--version'],env=env,capture_output=True,text=True,check=True)
            self.assertEqual(result.stdout.strip(),'2.1.0')
            self.assertEqual(list(target.iterdir()),[launcher])

    def test_listener_is_closed_after_watchdog_failure(self):
        import asyncio
        with tempfile.TemporaryDirectory() as td:
            sock=socket.socket()
            sock.bind(('127.0.0.1',0))
            port=sock.getsockname()[1]
            sock.close()
            app=App()
            app.fail_probe=True
            sdk=sdk_for(app)
            sdk.run_until_complete=lambda main: asyncio.run(main(None))
            config=dict(DEFAULT_CONFIG, home=Path(td)/'state', port=port)
            spec=importlib.util.spec_from_file_location('entrypoint2',ROOT/'iterm2-harness.py')
            module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            with patch.dict(sys.modules,{'iterm2':sdk}), patch('iterm2_harness.security.load_config',return_value=config):
                with self.assertRaises(APIError): module.run()
            with socket.socket() as probe:
                probe.bind(('127.0.0.1',port))

    def test_no_private_rpc_or_websocket_dependencies(self):
        sources='\n'.join(p.read_text() for p in (ROOT/'iterm2_harness').glob('*.py'))
        self.assertNotIn('iterm2.rpc._',sources)
        self.assertNotIn('connection.websocket',sources)
