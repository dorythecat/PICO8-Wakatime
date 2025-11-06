import time
from enum import Enum

import wakatime
import pico8_utils as pico8

DEBUG: bool = True # Set to False to disable debug output

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

def make_heartbeat(entity: str, total_lines: int, cursor_pos: int, edited_line: int) -> dict:
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
                   edited_line: int,
                   dry_run: bool = True,
                   run_cli: bool = False) -> None:
    """
    Create a SendHeartbeatsThread and either print the command (dry_run)
    or start the thread to actually invoke wakatime-cli (if installed).

    :param entity: The entity (file path or app name) for the heartbeat.
    :param total_lines: The size of the file in lines.
    :param cursor_pos: The current cursor position in the file.
    :param edited_line: The line number that was edited.
    :param dry_run: If True, only print the command without executing it.
    :param run_cli: If True, start the thread to send the heartbeat.
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
    api_key = thread.api_key
    if api_key:
        cmd.extend(['--key', api_key])
    if built.get('is_write'):
        cmd.append('--write')
    cmd.extend(['--project', built['project']['name']])
    cmd.extend(['--lineno', f"{built['lineno']}"])
    cmd.extend(['--cursorpos', f"{built['cursorpos']}"])
    cmd.extend(['--lines-in-file', f"{built['lines']}"])

    # Show obfuscated command for safety
    print('WakaTime command (obfuscated):', ' '.join(wakatime.obfuscate_apikey(cmd)))

    if dry_run:
        log(LogLevel.DEBUG, 'Dry run: not invoking wakatime-cli. Set dry_run=False to run it.')
        return

    if run_cli:
        log(LogLevel.INFO, 'Invoking wakatime-cli to send heartbeat...')
        thread.start()
        thread.join(10)
        log(LogLevel.INFO, 'Heartbeat sent.')


p8.on_mode_change(lambda mode: log(LogLevel.DEBUG, f'PICO-8 mode changed to: {mode}'))
p8.on_editor_submode_change(lambda mode: log(LogLevel.DEBUG, f'PICO-8 editor submode changed to: {mode}'))
p8.on_edit(lambda filename, total_lines, cursor_pos, edited_line: log(LogLevel.DEBUG,
    f'Edited line {edited_line} at cursor position {cursor_pos} in file {filename}, with {total_lines} lines'))
p8.on_load_file(lambda filename: log(LogLevel.DEBUG, f'PICO-8 loaded file: {filename}'))

while True:
    p8.update()
    time.sleep(0.1)