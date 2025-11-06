import time
from enum import Enum

import wakatime
import pico8_utils as pico8

DEBUG: bool = True # Set to False to disable debug output

# Timer for checking file changes when editing everything but code
change_check_timer: int = 1200 # 120 seconds = 2 minutes
last_file_hash: str = ''

class LogLevel(Enum):
    INFO = 'INFO'
    DEBUG = 'DEBUG'
    WARNING = 'WARNING'
    ERROR = 'ERROR'

p8: pico8.Pico8 = pico8.Pico8()

def log(level: LogLevel, message: str) -> None:
    """
    Log a message to the console if DEBUG is enabled.

    :param level: The log level (INFO, DEBUG, WARNING, ERROR).
    :param message: The message to log.
    :return: None
    """
    if level in [LogLevel.WARNING, LogLevel.ERROR] or DEBUG:
        print(f'[{level.value}] {message}')

def make_heartbeat(entity: str,
                   total_lines: int,
                   cursor_pos: int,
                   edited_line: int) -> dict:
    """
    Return a heartbeat dict compatible with wakatime.SendHeartbeatsThread.

    :param entity: The entity (file path or app name) for the heartbeat.
    :param total_lines: The size of the file in lines.
    :param cursor_pos: The current cursor position in the file.
    :param edited_line: The line number that was edited.
    :return: A dictionary representing the heartbeat.
    """
    return {
        'entity': entity,
        'timestamp': time.time(),
        'is_write': False, # TODO: Determine if the file was modified
        'lineno': edited_line,
        'cursorpos': cursor_pos,
        'lines_in_file': total_lines,
        'project': { 'name': entity },
        'folders': None
    }

def send_heartbeat(entity: str,
                   total_lines: int,
                   cursor_pos: int,
                   edited_line: int) -> None:
    """
    Create a SendHeartbeatsThread and either print the command (dry_run)
    or start the thread to actually invoke wakatime-cli (if installed).

    :param entity: The entity (file path or app name) for the heartbeat.
    :param total_lines: The size of the file in lines.
    :param cursor_pos: The current cursor position in the file.
    :param edited_line: The line number that was edited.
    :return: None
    """
    hb = make_heartbeat(entity, total_lines, cursor_pos, edited_line)
    thread = wakatime.SendHeartbeatsThread(hb)

    # Build the heartbeat the same way the thread will
    built = thread.build_heartbeat(**hb)

    # Construct the CLI command similar to SendHeartbeatsThread.send_heartbeats
    cmd = [
        wakatime.getCliLocation(),
        '--entity', built['entity'],
        '--entity-type', 'app',
        '--time', str('%f' % built['timestamp']),
        '--plugin', 'PICO8-Wakatime/' + wakatime.__version__,
        '--language', 'PICO-8'
    ]
    if thread.api_key:
        cmd.extend(['--key', thread.api_key])
    if built.get('is_write'):
        cmd.append('--write')
    if built.get('alternate_project'):
        cmd.extend(['--alternate-project', built['alternate_project']])
    cmd.extend(['--lineno', f"{built['lineno']}"])
    cmd.extend(['--cursorpos', f"{built['cursorpos']}"])
    cmd.extend(['--lines-in-file', f"{built['lines']}"])

    # Show obfuscated command for safety
    log(LogLevel.DEBUG, f'WakaTime command (obfuscated): {' '.join(wakatime.obfuscate_apikey(cmd))}')

    log(LogLevel.INFO, 'Invoking wakatime-cli to send heartbeat...')
    thread.start()
    thread.join(10)
    log(LogLevel.INFO, 'Heartbeat sent!')

def new_file_loaded(filename: str) -> None:
    """
    Callback for when a new file is loaded in PICO-8.

    :param filename: The name of the file that was loaded.
    :return: None
    """
    global last_file_hash, change_check_timer

    log(LogLevel.INFO, f'New file loaded: {filename}')
    last_file_hash = p8.file_hash
    change_check_timer = 1200 # Reset timer

p8.on_load_file(new_file_loaded) # Update last_file_hash and timer on file load
p8.on_edit(send_heartbeat) # Send heartbeat on code edits
while True:
    p8.update()
    change_check_timer -= 1
    if change_check_timer <= 0:
        change_check_timer = 1200 # Reset timer
        if p8.mode == pico8.Mode.EDITOR and p8.editor_submode != pico8.EditorMode.CODE:
            file_hash = p8.file_hash
            if file_hash != last_file_hash:
                last_file_hash = file_hash
                log(LogLevel.INFO, 'Detected file change in non-code editor mode.')
                send_heartbeat(
                    entity=p8.filename,
                    total_lines=p8.total_lines,
                    cursor_pos=p8.cursor_pos,
                    edited_line=p8.edited_line
                )
    time.sleep(0.1)