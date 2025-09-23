import os
from dotenv import load_dotenv
from termcolor import colored

# Load environment variables from .env file
load_dotenv()

# Function to print colored messages based on the COLOR environment variable
def print_colored(message, color_name, attrs=None):
    """
    Print colored messages if COLOR environment variable is set to '1'
    
    Args:
        message (str): The message to print
        color_name (str): Color name (red, green, yellow, blue, magenta, cyan, white) 
                         or legacy ColorMap attribute
        attrs (list): Optional attributes like ['bold', 'underline']
    """
    # Convert legacy ColorMap to actual color names
    color_mapping = {
        'red': 'red',
        'green': 'green', 
        'yellow': 'yellow',
        'blue': 'blue',
        'magenta': 'magenta',
        'cyan': 'cyan',
        'white': 'white'
    }
    
    # Use the color directly if it's a string, otherwise it's already a color name
    actual_color = color_mapping.get(color_name, color_name)
    
    if os.environ.get('COLOR') == '1':
        print(colored(message, actual_color, attrs=attrs))
    else:
        print(message)

# Convenience functions for common colors
def print_success(message):
    print_colored(message, 'green')

def print_error(message):
    print_colored(message, 'red')

def print_warning(message):
    print_colored(message, 'yellow')

def print_info(message):
    print_colored(message, 'magenta')

def print_header(message):
    print_colored(message, 'cyan', attrs=['bold'])

# Legacy compatibility - map old bcolors to termcolor names
class ColorMap:
    HEADER = 'cyan'
    OKBLUE = 'blue'
    OKCYAN = 'cyan'
    OKGREEN = 'green'
    WARNING = 'yellow'
    FAIL = 'red'
    BOLD = ['bold']