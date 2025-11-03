import psutil

def find_process() -> psutil.Process | None:
    for proc in psutil.process_iter():
        if ("pico8" in proc.name()):
            return proc
    return None

print(find_process())