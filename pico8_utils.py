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
import psutil, platform
from enum import Enum


# MEMORY ADDRESS CONSTANTS
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

class Pico8:
    """
    A class representing a PICO-8 instance, providing methods to read and handle memory.
    """
    process: psutil.Process = None

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

    def __init__(self):
        """
        Attempts to find the PICO-8 process by name.

        :raises RuntimeError: If PICO-8 process is not found.
        """
        for proc in psutil.process_iter():
            if "pico8" in proc.name():
                self.process = proc
        raise RuntimeError("PICO-8 process not found. Is PICO-8 running?")

    def read_memory(self, address: int, size: int) -> bytes:
        """
        Read `size` bytes from `address` in process `pid`.

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

            hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, self.process.pid)
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
                with open(f'/proc/{self.process.pid}/mem', 'rb') as fh:
                    fh.seek(address)
                    return fh.read(size)
            except Exception as e:
                raise OSError(f'Could not read /proc/{self.process.pid}/mem at {hex(address)}: {e}')
        else:
            raise NotImplementedError(f'Unsupported platform: {system}')

    def read_bool(self, address: int) -> bool:
        """
        Read a boolean (1 byte) from `address` in process `pid`.

        :param pid: Process ID to read from.
        :param address: Memory address to read.
        :return: Boolean value read from the process memory.
        :raises OSError: If reading fails.
        """
        return self.read_memory(address, 1) != b'\x00'

    def read_int(self, address: int, size: int = 4) -> int:
        """
        Read an integer of `size` bytes from `address` in process `pid`.

        :param pid: Process ID to read from.
        :param address: Memory address to read.
        :param size: Number of bytes to read. (Defaults to 4 for a 32-bit integer)
        :return: Integer value read from the process memory.
        :raises OSError: If reading fails.
        """
        return int.from_bytes(self.read_memory(address, size), byteorder='little')

    def read_filename(self) -> str:
        """
        Extract the code section from the PICO-8 process memory.

        :param pid: Process ID to read from.
        :return: Filename string read from the process memory.
        :raises OSError: If reading fails.
        :raises ValueError: If string terminator is not found.
        """
        # Read filename string (assumed max length 256 bytes)
        raw_bytes = self.read_process_memory(filename_address, 256)
        # Find terminator (.p8)
        terminator = raw_bytes.find(b'.p8\x00')
        if terminator != -1:
            raw_bytes = raw_bytes[:terminator]
        else:
            raise ValueError('Could not find string terminator for filename.')
        self.filename = raw_bytes.decode('utf-8', errors='ignore')
        return self.filename

    def read_code(self) -> str:
        """
        Extract the code section from the PICO-8 process memory.

        :param pid: Process ID to read from.
        :return: Code string read from the process memory.
        :raises OSError: If reading fails.
        :raises ValueError: If string terminator is not found.
        """
        code_size = self.read_int(file_size_address) + 128  # Just to be safe
        raw_bytes = self.read_memory(code_address, code_size)
        terminator = raw_bytes.find(b'\x00\x00')
        if terminator != -1:
            raw_bytes = raw_bytes[:terminator]
        else:
            raise ValueError('Could not find string terminator for code section.')
        self.code = raw_bytes.decode('utf-8', errors='ignore')
        return self.code

    def get_line_from_pos(self) -> int:
        """
        Get the line of code at the given cursor position.

        :param code: The full code string.
        :param cursor_pos: The cursor position in characters.
        :return: The line of code at the cursor position.
        """
        lines = self.code.splitlines(keepends=True)
        current_pos = 0
        for i, line in enumerate(lines):
            current_pos += len(line)
            if current_pos >= self.cursor_pos:
                return i + 1  # Line numbers start at 1
        return len(lines)