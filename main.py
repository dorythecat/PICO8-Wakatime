import psutil

# Find the process with "pico8" in its name
def find_process() -> psutil.Process | None:
    for proc in psutil.process_iter():
        if ("pico8" in proc.name()):
            return proc
    return None

# Print the I/O counters of the found process
print(find_process().io_counters())