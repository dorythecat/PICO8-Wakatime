# PICO8-Wakatime
Wakatime for PICO8 Fantasy Console (tested on 0.2.6)

# How to run
1. Make sure you have Python 3 installed on your system.
2. Open up PICO-8.
3. Just run `run.bat` (Windows) or `run.sh` (Linux/Mac).
4. Enjoy! :D

# About `pico8_utils.py`
To make this program work, with all the limitations of PICO-8,
I had to spoof memory addresses from PICO-8, by using Cheat Engine,
and even having to do a slight bit of disassembly of the PICO-8
executable.

Because I do not wish this task upon anyone else, the entire
`pico8_utils.py` file can be used as a standalone module to
help you interface with PICO-8's memory addresses, in case
you would ever need to do that, probably because you like
torturing yourself.

This module falls under the same license as the rest of the
code in this repository, just keep that in mind when using it.
Thank you. <3