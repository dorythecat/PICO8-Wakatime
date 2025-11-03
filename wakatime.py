""" ==========================================================
File:        WakaTime.py
Description: Automatic time tracking for PICO 8 (0.2.6)
Maintainer:  Dory
License:     GNU Affero General Public License v3.0
             (http://www.gnu.org/licenses/agpl-3.0.html)
==========================================================="""


__version__ = '0.0.1'

import json
import os
import platform
import re
import shutil
import ssl
import subprocess
import sys
import time
import threading
import traceback
import webbrowser
from subprocess import STDOUT, PIPE
from zipfile import ZipFile

import queue
from configparser import ConfigParser, Error as ConfigParserError
from urllib.request import Request, urlopen
from urllib.error import HTTPError


if sys.version_info[0] != 3: # Only Python 3 supported
    raise Exception(f'Unsupported Python version: {sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}')

is_win = platform.system() == 'Windows'

class Popen(subprocess.Popen):
    """Patched Popen to prevent opening cmd window on Windows platform."""

    def __init__(self, *args, **kwargs):
        if is_win:
            startupinfo = kwargs.get('startupinfo')
            try:
                startupinfo = startupinfo or subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            except AttributeError:
                pass
            kwargs['startupinfo'] = startupinfo
        super(Popen, self).__init__(*args, **kwargs)


# globals
ST_VERSION = int(sublime.version())
HOME_FOLDER = os.path.realpath(os.environ.get('WAKATIME_HOME') or os.path.expanduser('~'))
RESOURCES_FOLDER = os.path.join(HOME_FOLDER, '.wakatime')
CONFIG_FILE = os.path.join(HOME_FOLDER, '.wakatime.cfg')
INTERNAL_CONFIG_FILE = os.path.join(HOME_FOLDER, '.wakatime-internal.cfg')
GITHUB_RELEASES_STABLE_URL = 'https://api.github.com/repos/wakatime/wakatime-cli/releases/latest'
GITHUB_DOWNLOAD_PREFIX = 'https://github.com/wakatime/wakatime-cli/releases/download'
SETTINGS_FILE = 'WakaTime.sublime-settings'
SETTINGS = {}
LAST_HEARTBEAT = {
    'time': 0,
    'file': None,
    'is_write': False,
}
LAST_HEARTBEAT_SENT_AT = 0
LAST_FETCH_TODAY_CODING_TIME = 0
FETCH_TODAY_DEBOUNCE_COUNTER = 0
FETCH_TODAY_DEBOUNCE_SECONDS = 60
LATEST_CLI_VERSION = None
WAKATIME_CLI_LOCATION = None
HEARTBEATS = queue.Queue()
HEARTBEAT_FREQUENCY = 2  # minutes between logging heartbeat when editing same file
SEND_BUFFER_SECONDS = 30  # seconds between sending buffered heartbeats to API


# Log Levels
DEBUG = 'DEBUG'
INFO = 'INFO'
WARNING = 'WARNING'
ERROR = 'ERROR'


def parseConfigFile(configFile):
    """Returns a configparser.SafeConfigParser instance with configs
    read from the config file. Default location of the config file is
    at ~/.wakatime.cfg.
    """

    kwargs = {'strict': False}
    configs = ConfigParser(**kwargs)
    try:
        with open(configFile, 'r', encoding='utf-8') as fh:
            try:
                configs.read_file(fh)
                return configs
            except ConfigParserError:
                log(ERROR, traceback.format_exc())
                return None
    except IOError:
        log(DEBUG, f'Error: Could not read from config file {configFile}\n')
        return configs


class ApiKey(object):
    _key = None

    def read(self):
        if self._key:
            return self._key

        key = SETTINGS.get('api_key')
        if key:
            self._key = key
            return self._key

        configs = None
        try:
            configs = parseConfigFile(CONFIG_FILE)
            if configs:
                if configs.has_option('settings', 'api_key'):
                    key = configs.get('settings', 'api_key')
                    if key:
                        self._key = key
                        return self._key
        except:
            pass

        key = self.api_key_from_vault_cmd(configs)
        if key:
            self._key = key
            return self._key

        return self._key

    def api_key_from_vault_cmd(self, configs):
        vault_cmd = SETTINGS.get('api_key_vault_cmd')
        if not vault_cmd and configs:
            try:
                if configs.has_option('settings', 'api_key_vault_cmd'):
                    vault_cmd = configs.get('settings', 'api_key_vault_cmd')
            except:
                pass

        if not vault_cmd or not vault_cmd.strip():
            return None

        try:
            process = Popen(vault_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            stdout, stderr = process.communicate()
            retcode = process.poll()
            if retcode:
                log(ERROR, f'Vault command error ({retcode}): {stderr}')
                return None
            return stdout.strip() or None
        except:
            log(ERROR, traceback.format_exc())

        return None

    def write(self, key):
        global SETTINGS
        self._key = key
        SETTINGS.set('api_key', str(key))
        # TODO: Svae settings
        # sublime.save_settings(SETTINGS_FILE)


APIKEY = ApiKey()


def set_timeout(callback: callable, seconds: float) -> None:
    """
    Schedules callback to be called after seconds.

    :param callback: The function to call after the timeout.
    :param seconds: The number of seconds to wait before calling the callback.
    :return: None
    """
    def run():
        time.sleep(seconds)
        callback()
    threading.Thread(target=run).start()


def log(lvl, message):
    if lvl == DEBUG and not SETTINGS.get('debug'):
        return
    msg = message
    print(f'[WakaTime] [{lvl}] {msg}')

def obfuscate_apikey(command_list):
    cmd = list(command_list)
    apikey_index = None
    for num in range(len(cmd)):
        if cmd[num] == '--key':
            apikey_index = num + 1
            break
    if apikey_index is not None and apikey_index < len(cmd):
        cmd[apikey_index] = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX' + cmd[apikey_index][-4:]
    return cmd


def enough_time_passed(now, is_write):
    if now - LAST_HEARTBEAT['time'] > HEARTBEAT_FREQUENCY * 60:
        return True
    if is_write and now - LAST_HEARTBEAT['time'] > 2:
        return True
    return False


def find_folder_containing_file(folders, current_file):
    """Returns absolute path to folder containing the file.
    """

    parent_folder = None

    current_folder = current_file
    while True:
        for folder in folders:
            if os.path.realpath(os.path.dirname(current_folder)) == os.path.realpath(folder):
                parent_folder = folder
                break
        if parent_folder is not None:
            break
        if not current_folder or os.path.dirname(current_folder) == current_folder:
            break
        current_folder = os.path.dirname(current_folder)
    return parent_folder


def find_project_from_folders(folders: list, current_file: str) -> str | None:
    """
    Find project name from open folders.

    :param folders: List of absolute paths to open folders.
    :param current_file: Absolute path to current file.
    :return: Project name or None if not found.
    """

    folder = find_folder_containing_file(folders, current_file)
    return os.path.basename(folder) if folder else None

def handle_activity(view, is_write=False):
    window = view.window()
    if window is not None:
        entity = view.file_name()
        if entity:
            timestamp = time.time()
            last_file = LAST_HEARTBEAT['file']
            if entity != last_file or enough_time_passed(timestamp, is_write):
                project = window.project_data() if hasattr(window, 'project_data') else None
                folders = window.folders()
                append_heartbeat(entity, timestamp, is_write, view, project, folders)


def append_heartbeat(entity, timestamp, is_write, view, project, folders):
    global LAST_HEARTBEAT

    # add this heartbeat to queue
    heartbeat = {
        'entity': entity,
        'timestamp': timestamp,
        'is_write': is_write,
        'project': project,
        'folders': folders,
        'lines_in_file': view.rowcol(view.size())[0] + 1,
    }
    selections = view.sel()
    if selections and len(selections) > 0:
        rowcol = view.rowcol(selections[0].begin())
        row, col = rowcol[0] + 1, rowcol[1] + 1
        heartbeat['lineno'] = row
        heartbeat['cursorpos'] = col
    HEARTBEATS.put_nowait(heartbeat)

    # make this heartbeat the LAST_HEARTBEAT
    LAST_HEARTBEAT = {
        'file': entity,
        'time': timestamp,
        'is_write': is_write,
    }

    # process the queue of heartbeats in the future
    set_timeout(lambda: process_queue(timestamp), SEND_BUFFER_SECONDS)


def process_queue(timestamp):
    global LAST_HEARTBEAT_SENT_AT

    if not isCliInstalled():
        return

    # Prevent sending heartbeats more often than SEND_BUFFER_SECONDS
    now = int(time.time())
    if timestamp != LAST_HEARTBEAT['time'] and LAST_HEARTBEAT_SENT_AT > now - SEND_BUFFER_SECONDS:
        return
    LAST_HEARTBEAT_SENT_AT = now

    try:
        heartbeat = HEARTBEATS.get_nowait()
    except queue.Empty:
        return

    has_extra_heartbeats = False
    extra_heartbeats = []
    try:
        while True:
            extra_heartbeats.append(HEARTBEATS.get_nowait())
            has_extra_heartbeats = True
    except queue.Empty:
        pass

    thread = SendHeartbeatsThread(heartbeat)
    if has_extra_heartbeats:
        thread.add_extra_heartbeats(extra_heartbeats)
    thread.start()


class SendHeartbeatsThread(threading.Thread):
    """Non-blocking thread for sending heartbeats to api.
    """

    def __init__(self, heartbeat):
        threading.Thread.__init__(self)

        self.debug = SETTINGS.get('debug')
        self.api_key = APIKEY.read() or ''
        self.ignore = SETTINGS.get('ignore', [])
        self.include = SETTINGS.get('include', [])
        self.hidefilenames = SETTINGS.get('hidefilenames')
        self.proxy = SETTINGS.get('proxy')

        self.heartbeat = heartbeat
        self.has_extra_heartbeats = False

    def add_extra_heartbeats(self, extra_heartbeats):
        self.has_extra_heartbeats = True
        self.extra_heartbeats = extra_heartbeats

    def run(self):
        """Running in background thread."""

        self.send_heartbeats()

    def build_heartbeat(self, entity=None, timestamp=None, is_write=None,
                        lineno=None, cursorpos=None, lines_in_file=None,
                        project=None, folders=None):
        """Returns a dict for passing to wakatime-cli as arguments."""

        heartbeat = {
            'entity': entity,
            'timestamp': timestamp,
            'is_write': is_write,
        }

        if project and project.get('name'):
            heartbeat['alternate_project'] = project.get('name')
        elif folders:
            project_name = find_project_from_folders(folders, entity)
            if project_name:
                heartbeat['alternate_project'] = project_name

        if lineno is not None:
            heartbeat['lineno'] = lineno
        if cursorpos is not None:
            heartbeat['cursorpos'] = cursorpos
        if lines_in_file is not None:
            heartbeat['lines'] = lines_in_file

        return heartbeat

    def send_heartbeats(self):
        heartbeat = self.build_heartbeat(**self.heartbeat)
        ua = 'sublime/%d sublime-wakatime/%s' % (ST_VERSION, __version__)
        cmd = [
            getCliLocation(),
            '--entity', heartbeat['entity'],
            '--time', str('%f' % heartbeat['timestamp']),
            '--plugin', ua,
        ]
        if self.api_key:
            cmd.extend(['--key', str(bytes.decode(self.api_key.encode('utf8')))])
        if heartbeat['is_write']:
            cmd.append('--write')
        if heartbeat.get('alternate_project'):
            cmd.extend(['--alternate-project', heartbeat['alternate_project']])
        if heartbeat.get('lineno') is not None:
            cmd.extend(['--lineno', f'{heartbeat['lineno']}'])
        if heartbeat.get('cursorpos') is not None:
            cmd.extend(['--cursorpos', f'{heartbeat['cursorpos']}'])
        if heartbeat.get('lines') is not None:
            cmd.extend(['--lines-in-file', f'{heartbeat['lines']}'])
        for pattern in self.ignore:
            cmd.extend(['--exclude', pattern])
        for pattern in self.include:
            cmd.extend(['--include', pattern])
        if self.debug:
            cmd.append('--verbose')
        if self.hidefilenames:
            cmd.append('--hidefilenames')
        if self.proxy:
            cmd.extend(['--proxy', self.proxy])
        if self.has_extra_heartbeats:
            cmd.append('--extra-heartbeats')
            stdin = PIPE
            extra_heartbeats = json.dumps([self.build_heartbeat(**x) for x in self.extra_heartbeats])
            inp = f'{extra_heartbeats}\n'
        else:
            stdin = None
            inp = None

        log(DEBUG, ' '.join(obfuscate_apikey(cmd)))
        try:
            process = Popen(cmd, stdin=stdin, stdout=PIPE, stderr=STDOUT)
            output, _err = process.communicate(input=inp)
            retcode = process.poll()
            if (not retcode or retcode == 102 or retcode == 112) and not output:
                self.sent()
            else:
                update_status_bar('Error')
            if retcode:
                log(DEBUG if retcode == 102 or retcode == 112 else ERROR, f'wakatime-core exited with status: {retcode}')
            if output:
                log(ERROR, f'wakatime-core output: {output}')
        except:
            log(ERROR, sys.exc_info()[1])
            update_status_bar('Error')

    def sent(self):
        update_status_bar('OK')


def plugin_loaded():
    global SETTINGS
    SETTINGS = sublime.load_settings(SETTINGS_FILE)

    log(INFO, 'Initializing WakaTime plugin v%s' % __version__)
    update_status_bar('Initializing...')

    UpdateCLI().start()

    after_loaded()


def after_loaded():
    if not prompt_api_key():
        set_timeout(after_loaded, 0.5)
    update_status_bar('OK')


# need to call plugin_loaded because only ST3 will auto-call it
if ST_VERSION < 3000:
    plugin_loaded()


class WakatimeListener(sublime_plugin.EventListener):

    def on_post_save(self, view):
        handle_activity(view, is_write=True)

    def on_selection_modified(self, view):
        if is_view_active(view):
            handle_activity(view)

    def on_modified(self, view):
        if is_view_active(view):
            handle_activity(view)


class WakatimeDashboardCommand(sublime_plugin.ApplicationCommand):

    def run(self):
        webbrowser.open_new_tab('https://wakatime.com/dashboard')


class UpdateCLI(threading.Thread):
    """Non-blocking thread for downloading latest wakatime-cli from GitHub.
    """

    def run(self):
        if isCliLatest():
            return

        log(INFO, 'Downloading wakatime-cli...')

        if os.path.isdir(os.path.join(RESOURCES_FOLDER, 'wakatime-cli')):
            shutil.rmtree(os.path.join(RESOURCES_FOLDER, 'wakatime-cli'))

        if not os.path.exists(RESOURCES_FOLDER):
            os.makedirs(RESOURCES_FOLDER)

        try:
            url = cliDownloadUrl()
            log(DEBUG, f'Downloading wakatime-cli from {url}')
            zip_file = os.path.join(RESOURCES_FOLDER, 'wakatime-cli.zip')
            download(url, zip_file)

            if isCliInstalled():
                try:
                    os.remove(getCliLocation())
                except:
                    log(DEBUG, traceback.format_exc())

            log(INFO, 'Extracting wakatime-cli...')
            with ZipFile(zip_file) as zf:
                zf.extractall(RESOURCES_FOLDER)

            if not is_win:
                os.chmod(getCliLocation(), 509)  # 755

            try:
                os.remove(os.path.join(RESOURCES_FOLDER, 'wakatime-cli.zip'))
            except:
                log(DEBUG, traceback.format_exc())
        except:
            log(DEBUG, traceback.format_exc())

        createSymlink()

        log(INFO, 'Finished extracting wakatime-cli.')


def getCliLocation():
    global WAKATIME_CLI_LOCATION

    if not WAKATIME_CLI_LOCATION:
        binary = f'wakatime-cli-{platform.system().lower()}-{architecture()}' + ('.exe' if is_win else '')
        WAKATIME_CLI_LOCATION = os.path.join(RESOURCES_FOLDER, binary)
    return WAKATIME_CLI_LOCATION


def architecture():
    arch = platform.machine() or platform.processor()
    if arch == 'armv7l':
        return 'arm'
    if arch == 'aarch64':
        return 'arm64'
    if 'arm' in arch:
        return 'arm64' if sys.maxsize > 2**32 else 'arm'
    return 'amd64' if sys.maxsize > 2**32 else '386'


def isCliInstalled():
    return os.path.exists(getCliLocation())


def isCliLatest():
    if not isCliInstalled():
        return False

    args = [getCliLocation(), '--version']
    try:
        stdout, stderr = Popen(args, stdout=PIPE, stderr=PIPE).communicate()
    except:
        return False
    stdout = (stdout or b'') + (stderr or b'')
    localVer = extractVersion(stdout.decode('utf-8'))
    if not localVer:
        log(DEBUG, 'Local wakatime-cli version not found.')
        return False

    log(INFO, f'Current wakatime-cli version is {localVer}')
    log(INFO, 'Checking for updates to wakatime-cli...')

    remoteVer = getLatestCliVersion()

    if not remoteVer:
        return True

    if remoteVer == localVer:
        log(INFO, 'wakatime-cli is up to date.')
        return True

    log(INFO, f'Found an updated wakatime-cli {remoteVer}')
    return False


def getLatestCliVersion():
    global LATEST_CLI_VERSION

    if LATEST_CLI_VERSION:
        return LATEST_CLI_VERSION

    configs, last_modified, last_version = None, None, None
    try:
        configs = parseConfigFile(INTERNAL_CONFIG_FILE)
        if configs:
            last_modified, last_version = lastModifiedAndVersion(configs)
    except:
        log(DEBUG, traceback.format_exc())

    try:
        headers, contents, code = request(GITHUB_RELEASES_STABLE_URL, last_modified=last_modified)

        log(DEBUG, f'GitHub API Response {code}')

        if code == 304:
            LATEST_CLI_VERSION = last_version
            return last_version

        data = json.loads(contents.decode('utf-8'))

        ver = data['tag_name']
        log(DEBUG, f'Latest wakatime-cli version from GitHub: {ver}')

        if configs:
            last_modified = headers.get('Last-Modified')
            if not configs.has_section('internal'):
                configs.add_section('internal')
            configs.set('internal', 'cli_version', ver)
            configs.set('internal', 'cli_version_last_modified', last_modified)
            with open(INTERNAL_CONFIG_FILE, 'w', encoding='utf-8') as fh:
                configs.write(fh)

        LATEST_CLI_VERSION = ver
        return ver
    except:
        log(DEBUG, traceback.format_exc())
        return None


def lastModifiedAndVersion(configs):
    last_modified, last_version = None, None
    if configs.has_option('internal', 'cli_version'):
        last_version = configs.get('internal', 'cli_version')
    if last_version and configs.has_option('internal', 'cli_version_last_modified'):
        last_modified = configs.get('internal', 'cli_version_last_modified')
    if last_modified and last_version and extractVersion(last_version):
        return last_modified, last_version
    return None, None


def extractVersion(text):
    pattern = re.compile(r"([0-9]+\.[0-9]+\.[0-9]+)")
    match = pattern.search(text)
    return f'v{match.group(1)}' if match else None


def cliDownloadUrl():
    osname = platform.system().lower()
    arch = architecture()

    validCombinations = [
      'darwin-amd64',
      'darwin-arm64',
      'freebsd-386',
      'freebsd-amd64',
      'freebsd-arm',
      'linux-386',
      'linux-amd64',
      'linux-arm',
      'linux-arm64',
      'netbsd-386',
      'netbsd-amd64',
      'netbsd-arm',
      'openbsd-386',
      'openbsd-amd64',
      'openbsd-arm',
      'openbsd-arm64',
      'windows-386',
      'windows-amd64',
      'windows-arm64',
    ]
    check = f'{osname}-{arch}'
    if check not in validCombinations:
        reportMissingPlatformSupport(osname, arch)

    version = getLatestCliVersion()

    return f'{GITHUB_DOWNLOAD_PREFIX}/{version}/wakatime-cli-{osname}-{arch}.zip'


def reportMissingPlatformSupport(osname, arch):
    url = f'https://api.wakatime.com/api/v1/cli-missing?osname={osname}&architecture={arch}&plugin=pico8'
    request(url)


def request(url, last_modified=None):
    req = Request(url)
    req.add_header('User-Agent', 'github.com/dorythecat/PICO8-Wakatime')

    proxy = SETTINGS.get('proxy')
    if proxy:
        req.set_proxy(proxy, 'https')

    if last_modified:
        req.add_header('If-Modified-Since', last_modified)

    try:
        resp = urlopen(req)
        headers = resp.headers
        return headers, resp.read(), resp.getcode()
    except HTTPError as err:
        if err.code == 304:
            return None, None, 304
        log(DEBUG, err.read().decode())
        raise
    except IOError:
        raise


def download(url, filePath):
    req = Request(url)
    req.add_header('User-Agent', 'github.com/dorythecat/PICO8-Wakatime')

    proxy = SETTINGS.get('proxy')
    if proxy:
        req.set_proxy(proxy, 'https')

    with open(filePath, 'wb') as fh:
        try:
            resp = urlopen(req)
            fh.write(resp.read())
        except HTTPError as err:
            if err.code == 304:
                return None, None, 304
            log(DEBUG, err.read().decode())
            raise
        except IOError:
            raise


def is_symlink(path):
    try:
        return os.is_symlink(path)
    except:
        return False


def createSymlink():
    link = os.path.join(RESOURCES_FOLDER, 'wakatime-cli')
    if is_win:
        link = link + '.exe'
    elif os.path.exists(link) and is_symlink(link):
        return  # don't re-create symlink on Unix-like platforms

    try:
        os.symlink(getCliLocation(), link)
    except:
        try:
            shutil.copy2(getCliLocation(), link)
            if not is_win:
                os.chmod(link, 509)  # 755
        except:
            log(WARNING, traceback.format_exc())


class SSLCertVerificationDisabled(object):
    def __enter__(self):
        self.original_context = ssl._create_default_https_context
        ssl._create_default_https_context = ssl._create_unverified_context

    def __exit__(self, *args, **kwargs):
        ssl._create_default_https_context = self.original_context
