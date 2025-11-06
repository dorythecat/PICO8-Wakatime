"""
----------------------------
PICO-8 Utility Functions
----------------------------
This module provides utility functions for working with PICO-8,
by using memory manipulation techniques. Its main use is for
dorythecat's PICO-8 Wakatime plugin, but it can be used
in other projects as well, under the plugin's license.
----------------------------
"""
import psutil, platform, os
from enum import Enum


# MEMORY ADDRESS CONSTANTS
editor_window_address = 0x0051D0C8 # Address indicating EDITOR sub-mode (0 if not editor)
game_mode_address = 0x00866A28     # Address indicating GAME mode
cursor_pos_address = 0x005D0274    # Address for cursor position in EDITOR mode
file_size_address = 0x005D0264     # Address for file size in EDITOR mode, in characters
filename_address = 0x005574B2      # Address for filename string in EDITOR mode

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

class Pico8:
    """
    A class representing a PICO-8 instance, providing methods to read and handle memory.
    """
    mode: Mode = Mode.CONSOLE
    editor_submode: EditorMode = EditorMode.CODE
    cursor_pos: int = -1
    file_size: int = -1
    filename: str = ''

    _prev_mode: Mode = Mode.CONSOLE
    _prev_editor_submode: EditorMode = EditorMode.CODE
    _last_cursor_pos: int = -1
    _last_file_size: int = -1
    _last_filename: str = ''
    _code: str = ''

    # Callback functions
    _mode_change_callbacks: list[callable] = []
    _editor_submode_change_callbacks: list[callable] = []
    _edit_callbacks: list[callable] = []
    _load_file_callbacks: list[callable] = []

    # Find running process
    def __init__(self) -> None:
        """
        Attempts to find the PICO-8 process by name.

        :raises RuntimeError: If PICO-8 process is not found.
        """
        for proc in psutil.process_iter():
            if "pico8" in proc.name():
                self._process = proc
                return
        raise RuntimeError("PICO-8 process not found. Is PICO-8 running?")

    # Utility methods to read and process memory data
    def read_memory(self, address: int, size: int) -> bytes:
        """
        Read `size` bytes from `address` in the PICO-8 process.

        On Windows uses ReadProcessMemory via ctypes. On Unix tries /proc/<pid>/mem (may require root or ptrace).

        :param address: Memory address to read from.
        :param size: Number of bytes to read.
        :return: Bytes read from the specified memory address.
        :raises OSError: If reading memory fails.
        :raises NotImplementedError: If the platform is unsupported.
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

            hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, self._process.pid)
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
                with open(f'/proc/{self._process.pid}/mem', 'rb') as fh:
                    fh.seek(address)
                    return fh.read(size)
            except Exception as e:
                raise OSError(f'Unable to read /proc/{self._process.pid}/mem at {hex(address)}: {e}')
        else:
            raise NotImplementedError(f'Unsupported platform: {system}')

    def read_bool(self, address: int) -> bool:
        """
        Read a boolean (1 byte) from `address`.

        :param address: Memory address to read.
        :return: Boolean value read from the process memory.
        :raises OSError: If reading fails.
        """
        return self.read_memory(address, 1) != b'\x00'

    def read_int(self, address: int, size: int = 4) -> int:
        """
        Read an integer of `size` bytes from `address` in process `pid`.

        :param address: Memory address to read.
        :param size: Number of bytes to read. (Defaults to 4 for a 32-bit integer)
        :return: Integer value read from the process memory.
        :raises OSError: If reading fails.
        """
        return int.from_bytes(self.read_memory(address, size), byteorder='little')

    def read_filename(self) -> str:
        """
        Extract the code section from the PICO-8 process memory.

        :return: Filename string read from the process memory.
        :raises OSError: If reading fails.
        :raises ValueError: If string terminator is not found.
        """
        # Read filename string (assumed max length 256 bytes)
        raw_bytes = self.read_memory(filename_address, 256)
        # Find terminator (.p8)
        terminator = raw_bytes.find(b'.p8\x00')
        if terminator != -1:
            raw_bytes = raw_bytes[:terminator]
        else:
            raise ValueError('Unable to find .p8 extension for filename.')
        self.filename = raw_bytes.decode('utf-8', errors='ignore')
        return self.filename

    def read_code(self) -> str:
        """
        Extract the code section from its file.

        :return: Code string read from the file.
        :raises OSError: If reading fails.
        :raises ValueError: If string terminator is not found.
        """
        code_file = self.filename + '.p8'
        carts_path = os.path.expandvars(
            os.path.join('%APPDATA%' if platform.system() == 'Windows' else '~', 'pico-8', 'carts')
        )
        full_path = ''
        for root, dirs, files in os.walk(carts_path):
            if code_file in files:
                full_path = os.path.join(root, code_file)
                break
        if full_path == '' or not os.path.isfile(full_path):
            raise OSError(f'Could not find .p8 file!')
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                code_start = content.find('__lua__')
                code_end = content.find('__gfx__')
                if code_start == -1:
                    raise ValueError(f'Unable to find code delimiters in \"{full_path}\"')
                self._code = content[code_start + len('__lua__'):code_end].lstrip('\n')
                return self._code
        except Exception as e:
            raise OSError(f'Unable to read code from file \"{full_path}\", encountered exception: {e}')

    @property
    def total_lines(self) -> int:
        """
        Get the total number of lines in the currently loaded code.

        :return: Total number of lines in the code.
        """
        return len(self._code.splitlines(True))

    @property
    def edited_line(self) -> int:
        """
        Get the currently edited line number based on the current cursor position.

        :return: Line number being edited.
        """
        lines = self._code.splitlines(True)
        current_pos = 0
        for i, line in enumerate(lines):
            current_pos += len(line)
            if current_pos > self.cursor_pos:
                return i + 1
        return len(lines)

    # Event hooks
    def on_mode_change(self, callback: callable) -> None:
        """
        Register a callback for mode change events.

        :param callback: The callback function to invoke on mode change.
        """
        self._mode_change_callbacks.append(callback)

    def on_editor_submode_change(self, callback: callable) -> None:
        """
        Register a callback for editor sub-mode change events.

        :param callback: The callback function to invoke on editor sub-mode change.
        """
        self._editor_submode_change_callbacks.append(callback)

    def on_edit(self, callback: callable) -> None:
        """
        Register a callback for edit line change events.

        :param callback: The callback function to invoke on edit line change.
        """
        self._edit_callbacks.append(callback)

    def on_load_file(self, callback: callable) -> None:
        """
        Register a callback for file load events.

        :param callback: The callback function to invoke on file load.
        """
        self._load_file_callbacks.append(callback)

    # Main update loop
    def update(self) -> None:
        """
        Update the PICO-8 state by reading memory and detecting changes.
        """
        try:
            self.read_filename()
            if self.filename != self._last_filename:
                [callback(self.filename) for callback in self._load_file_callbacks]
                self._last_filename = self.filename

            editor_window = self.read_int(editor_window_address)
            if editor_window > 0:
                self.mode = Mode.EDITOR
                self.editor_submode = EditorMode(editor_window)
                if self.editor_submode != self._prev_editor_submode:
                    [callback(self.editor_submode) for callback in self._editor_submode_change_callbacks]
                    self._prev_editor_submode = self.editor_submode

                if self.editor_submode == EditorMode.CODE:
                    self.file_size = self.read_int(file_size_address)
                    if self.file_size != self._last_file_size:
                        self.read_code()  # Only need to read code when file size changes
                        self.cursor_pos = self.read_int(cursor_pos_address)
                        [callback(self.filename, self.total_lines, self.cursor_pos, self.edited_line) for callback in self._edit_callbacks]
                        self._last_file_size = self.file_size
            elif self.read_bool(game_mode_address):
                self.mode = Mode.GAME
            else:
                self.mode = Mode.CONSOLE

            if self.mode != self._prev_mode:
                [callback(self.mode) for callback in self._mode_change_callbacks]
                self._prev_mode = self.mode
        except Exception as e:
            print(f'Error updating PICO-8 state: {e}')
            raise