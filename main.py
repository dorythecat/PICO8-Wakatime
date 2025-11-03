import os
import time
import psutil
import wakatime

# Find the process with "pico8" in its name
def find_process() -> psutil.Process | None:
    for proc in psutil.process_iter():
        if "pico8" in proc.name():
            return proc
    return None


def make_test_heartbeat(entity: str) -> dict:
    """Return a heartbeat dict compatible with wakatime.SendHeartbeatsThread."""
    return {
        'entity': os.path.abspath(entity),
        'timestamp': time.time(),
        'is_write': False,
        'lineno': 1,
        'cursorpos': 1,
        'lines_in_file': 1,
        'project': { 'name': 'Test Project' },
        'folders': None,
    }


def send_test_heartbeat(entity: str, dry_run: bool = True, run_cli: bool = False) -> None:
    """
    Create a SendHeartbeatsThread and either print the command (dry_run)
    or start the thread to actually invoke wakatime-cli (if installed).
    """
    hb = make_test_heartbeat(entity)
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


if __name__ == '__main__':
    # Prefer testing with pico8 process if found, otherwise use this file as the entity
    proc = None
    try:
        proc = find_process()
    except Exception as e:
        print('Warning: could not query processes:', e)

    if proc is not None:
        try:
            entity = proc.exe() or proc.cmdline()[0]
        except Exception as e:
            print('Warning: could not get pico8 process executable:', e)
            entity = __file__
        print('Found pico8 process, using entity:', entity)
    else:
        entity = __file__
        print('No pico8 process found, using current file as entity:', entity)

    # By default do a dry-run. Change to dry_run=False and run_cli=True to actually invoke wakatime-cli.
    send_test_heartbeat(entity, dry_run=False, run_cli=True)
