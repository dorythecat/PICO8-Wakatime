import os
import time

import wakatime

def make_heartbeat(entity: str) -> dict:
    """
    Return a heartbeat dict compatible with wakatime.SendHeartbeatsThread.

    :param entity: The entity (file path or app name) for the heartbeat.
    :return: A dictionary representing the heartbeat.
    """
    global edited_line, cursor_pos, file_size, filename

    return {
        'entity': os.path.abspath(entity),
        'timestamp': time.time(),
        'is_write': False, # TODO: Determine if the file was modified
        'lineno': edited_line,
        'cursorpos': cursor_pos,
        'lines_in_file': file_size,
        'project': { 'name': filename },
        'folders': None
    }

def send_heartbeat(entity: str, dry_run: bool = True, run_cli: bool = False) -> None:
    """
    Create a SendHeartbeatsThread and either print the command (dry_run)
    or start the thread to actually invoke wakatime-cli (if installed).
    """
    hb = make_heartbeat(entity)
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
        '--languague', 'PICO-8'
    ]
    api_key = thread.api_key
    if api_key:
        cmd.extend(['--key', str(bytes.decode(api_key.encode('utf8')))])
    if built.get('is_write'):
        cmd.append('--write')
    if built.get('alternate_project'):
        cmd.extend(['--alternate-project', built['alternate_project']])
    if built.get('lineno') is not None:
        cmd.extend(['--lineno', f"{built['lineno']}"])
    if built.get('cursorpos') is not None:
        cmd.extend(['--cursorpos', f"{built['cursorpos']}"])
    if built.get('lines') is not None:
        cmd.extend(['--lines-in-file', f"{built['lines']}"])

    # Show obfuscated command for safety
    print('WakaTime command (obfuscated):', ' '.join(wakatime.obfuscate_apikey(cmd)))

    if dry_run:
        print('Dry run: not invoking wakatime-cli. Set dry_run=False to run it.')
        return

    if not wakatime.isCliInstalled():
        print('wakatime-cli not found at', wakatime.getCliLocation())
        return

    if run_cli:
        print('Starting background thread to send heartbeat...')
        thread.start()
        thread.join(timeout=10)
        print('Thread finished.')
