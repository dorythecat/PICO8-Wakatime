import os
import time
import psutil
import platform
import wakatime
from enum import Enum

# CONSTANTS
editor_window_address = 0x0051D0C8 # Address indicating EDITOR sub-mode (0 if not editor)
game_mode_address = 0x00866A28     # Address indicating GAME mode
cursor_pos_address = 0x005D0274    # Address for cursor position in EDITOR mode
file_size_address = 0x005D0264     # Address for file size in EDITOR mode, in characters
filename_address = 0x005574B2      # Address for filename string in EDITOR mode
code_address = 0x10480F30          # Address where code section starts in memory

# HELPER ENUMS
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

# GLOBAL VARIABLES
mode: Mode = Mode.CONSOLE
prev_mode: Mode = Mode.CONSOLE

editor_submode: EditorMode = EditorMode.CODE
prev_editor_submode: EditorMode = EditorMode.CODE

cursor_pos: int = -1
last_cursor_pos: int = -1

file_size: int = -1
last_file_size: int = -1

filename: str = ''
last_filename: str = ''

code: str = ''
edited_line: int = -1

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

def read_process_memory_bool(pid: int, address: int) -> bool:
    """
    Read a boolean (1 byte) from `address` in process `pid`.

    :param pid: Process ID to read from.
    :param address: Memory address to read.
    :return: Boolean value read from the process memory.
    :raises OSError: If reading fails.
    """
    return read_process_memory(pid, address, 1) != b'\x00'

def read_process_memory_int(pid: int, address: int, size: int = 4) -> int:
    """
    Read an integer of `size` bytes from `address` in process `pid`.

    :param pid: Process ID to read from.
    :param address: Memory address to read.
    :param size: Number of bytes to read. (Defaults to 4 for a 32-bit integer)
    :return: Integer value read from the process memory.
    :raises OSError: If reading fails.
    """
    return int.from_bytes(read_process_memory(pid, address, size), byteorder='little')

def extract_filename(pid: int) -> str:
    """
    Extract the code section from the PICO-8 process memory.

    :param pid: Process ID to read from.
    :return: Filename string read from the process memory.
    :raises OSError: If reading fails.
    :raises ValueError: If string terminator is not found.
    """
    # Read filename string (assumed max length 256 bytes)
    raw_bytes = read_process_memory(pid, filename_address, 256)
    # Find terminator (.p8)
    terminator = raw_bytes.find(b'.p8\x00')
    if terminator != -1:
        raw_bytes = raw_bytes[:terminator]
    else:
        raise ValueError('Could not find string terminator for filename.')
    return raw_bytes.decode('utf-8', errors='ignore')

def read_code(pid: int) -> str:
    """
    Extract the code section from the PICO-8 process memory.

    :param pid: Process ID to read from.
    :return: Code string read from the process memory.
    :raises OSError: If reading fails.
    :raises ValueError: If string terminator is not found.
    """
    code_size = read_process_memory_int(pid, file_size_address) + 128  # Just to be safe
    raw_bytes = read_process_memory(pid, code_address, code_size)
    terminator = raw_bytes.find(b'\x00\x00')
    if terminator != -1:
        raw_bytes = raw_bytes[:terminator]
    else:
        raise ValueError('Could not find string terminator for code section.')
    return raw_bytes.decode('utf-8', errors='ignore')

def get_line_from_pos(code: str, cursor_pos: int) -> int:
    """
    Get the line of code at the given cursor position.

    :param code: The full code string.
    :param cursor_pos: The cursor position in characters.
    :return: The line of code at the cursor position.
    """
    lines = code.splitlines(keepends=True)
    current_pos = 0
    for i, line in enumerate(lines):
        current_pos += len(line)
        if current_pos >= cursor_pos:
            return i + 1  # Line numbers start at 1
    return len(lines)

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

while True:
    try:
        proc = find_process()
        pid = proc.pid
        filename = extract_filename(pid)
        if filename != last_filename:
            print(f'Loaded file: {filename}')
            last_filename = filename
        editor_window = read_process_memory_int(pid, editor_window_address)
        if editor_window > 0:
            mode = Mode.EDITOR
            editor_submode = EditorMode(editor_window)
            if editor_submode != prev_editor_submode:
                print(f'PICO-8 editor sub-mode changed to: {editor_submode.name}')
                prev_editor_submode = editor_submode
            if editor_submode == EditorMode.CODE:
                file_size = read_process_memory_int(pid, file_size_address)
                if file_size != last_file_size:
                    print(f'File size changed to: {file_size} characters')
                    last_file_size = file_size

                    code = read_code(pid) # Only need to read code when file size changes
                    edited_line = get_line_from_pos(code, cursor_pos)
                    if edited_line != -1:
                        print(f'Code edited at line: {edited_line}')
        elif read_process_memory_bool(pid, game_mode_address):
            mode = Mode.GAME
        else:
            mode = Mode.CONSOLE
        if mode != prev_mode:
            print(f'PICO-8 mode changed to: {mode.name}')
            prev_mode = mode
        if mode == Mode.EDITOR and editor_submode == EditorMode.CODE:
            cursor_pos = read_process_memory_int(pid, cursor_pos_address)
            if cursor_pos != last_cursor_pos:
                print(f'Cursor position changed to: {cursor_pos}' + (' (EOF)' if cursor_pos == file_size else ''))
                last_cursor_pos = cursor_pos
        time.sleep(0.1)
    except Exception as e:
        print('Error reading process memory:', e)
        raise
