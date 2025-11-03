import os
import time
import psutil
import platform
import wakatime
from enum import Enum

editor_window_address = 0x0051D0C8 # Address indicating EDITOR sub-mode (0 if not editor)
game_mode_address = 0x00866A28   # Address indicating GAME mode
cursor_pos_address = 0x005D0274  # Address for cursor position in EDITOR mode

# Find the process with "pico8" in its name
def find_process() -> psutil.Process:
    """
    Attempts to find the PICO-8 process by name.

    :return: psutil.Process object for PICO-8.
    :raises RuntimeError: If PICO-8 process is not found.
    """
    for proc in psutil.process_iter():
        if "pico8" in proc.name():
            return proc
    raise RuntimeError("PICO-8 process not found.")

def read_process_memory(pid: int, address: int, size: int) -> bytes:
    """
    Read `size` bytes from `address` in process `pid`.

    On Windows uses ReadProcessMemory via ctypes. On Unix tries /proc/<pid>/mem (may require root or ptrace).

    :param pid: Process ID to read from.
    :param address: Memory address to read.
    :param size: Number of bytes to read.
    :return: Bytes read from the process memory.
    :raises OSError: If reading fails.
    :raises NotImplementedError: If platform is unsupported.
    """
    system = platform.system()
    if system == 'Windows':
        import ctypes
        from ctypes import wintypes

        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        OpenProcess = kernel32.OpenProcess
        OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        OpenProcess.restype = wintypes.HANDLE

        ReadProcessMemory = kernel32.ReadProcessMemory
        ReadProcessMemory.argtypes = [wintypes.HANDLE,
                                      wintypes.LPCVOID,
                                      wintypes.LPVOID,
                                      ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_size_t)]
        ReadProcessMemory.restype = wintypes.BOOL

        CloseHandle = kernel32.CloseHandle

        hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not hProcess:
            err = ctypes.get_last_error()
            raise OSError(f'OpenProcess failed, last_error={err}')

        try:
            buf = (ctypes.c_ubyte * size)()
            bytesRead = ctypes.c_size_t(0)
            success = ReadProcessMemory(hProcess, ctypes.c_void_p(address), buf, size, ctypes.byref(bytesRead))
            if not success:
                err = ctypes.get_last_error()
                raise OSError(f'ReadProcessMemory failed, last_error={err}')
            return bytes(bytearray(buf))[:bytesRead.value]
        finally:
            CloseHandle(hProcess)
    elif system in ('Linux', 'Darwin'):
        # Attempt to read from /proc/<pid>/mem (Linux/Unix). This may require root or ptrace permissions.
        try:
            with open(f'/proc/{pid}/mem', 'rb') as fh:
                fh.seek(address)
                return fh.read(size)
        except Exception as e:
            raise OSError(f'Could not read /proc/{pid}/mem at {hex(address)}: {e}')
    else:
        raise NotImplementedError(f'Unsupported platform: {system}')

class Mode(Enum):
    CONSOLE = 0
    EDITOR = 1
    GAME = 2

class EditorMode(Enum):
    NOT_EDITOR = 0
    CODE = 1
    SPRITES = 2
    MAP = 3
    SFX = 4
    MUSIC = 5

mode: Mode = Mode.CONSOLE
prev_mode: Mode = Mode.CONSOLE

editor_submode: EditorMode = EditorMode.CODE
prev_editor_submode: EditorMode = EditorMode.CODE

while True:
    try:
        proc = find_process()
        pid = proc.pid
        editor_window_byte = read_process_memory(pid, editor_window_address, 4)
        editor_window = int.from_bytes(editor_window_byte, byteorder='little')
        game_mode_byte = read_process_memory(pid, game_mode_address, 1)
        if editor_window != 0:
            mode = Mode.EDITOR
            editor_submode = EditorMode(editor_window)
            if editor_submode != prev_editor_submode:
                print(f'PICO-8 editor sub-mode changed to: {editor_submode.name}')
                prev_editor_submode = editor_submode
        elif game_mode_byte == b'\x01':
            mode = Mode.GAME
        else:
            mode = Mode.CONSOLE
        if mode != prev_mode:
            print(f'PICO-8 mode changed to: {mode.name}')
            prev_mode = mode
        if mode == Mode.EDITOR and editor_submode == EditorMode.CODE:
            cursor_bytes = read_process_memory(pid, cursor_pos_address, 4)
            cursor_pos = int.from_bytes(cursor_bytes, byteorder='little')
            print(f'Cursor position in EDITOR mode: {cursor_pos}')
        time.sleep(0.1)
    except Exception as e:
        print('Error reading process memory:', e)
        raise
'''
def make_test_heartbeat(entity: str) -> dict:
    """Return a heartbeat dict compatible with wakatime.SendHeartbeatsThread."""
    return {
        'entity': os.path.abspath(entity),
        'timestamp': time.time(),
        'is_write': False,
        'lineno': 1,
        'cursorpos': 1,
        'lines_in_file': 1,
        'project': { 'name': 'PICO-8 Test Project' },
        'folders': None
    }

def send_heartbeat(entity: str, dry_run: bool = True, run_cli: bool = False) -> None:
    """
    Create a SendHeartbeatsThread and either print the command (dry_run)
    or start the thread to actually invoke wakatime-cli (if installed).
    """
    hb = make_test_heartbeat(entity) # TODO: Make actual heartbeat data
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
            raise RuntimeError('Could not get PICO-8 process executable for testing.')
    else:
        raise RuntimeError('Could not get PICO-8 process executable for testing.')

    # By default do a dry-run. Change to dry_run=False and run_cli=True to actually invoke wakatime-cli.
    send_heartbeat(entity, dry_run=False, run_cli=True)
'''