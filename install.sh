#!/bin/sh

# Install all the python requeirements in a .env

# Load environment variables from .env file if it exists
if [ -f .env ]; then
    set -a  # automatically export all variables
    . ./.env
    set +a  # stop automatically exporting
fi

# Colors
if [ "$COLOR" = "1" ]; then
    # Text Colors
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[0;37m'

    # Bold Colors
    BOLD_RED='\033[1;31m'
    BOLD_GREEN='\033[1;32m'
    BOLD_YELLOW='\033[1;33m'
    BOLD_BLUE='\033[1;34m'
    
    # Reset color
    NC='\033[0m' # No Color
else
    # Text Colors
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    PURPLE=''
    CYAN=''
    WHITE=''

    # Bold Colors
    BOLD_RED=''
    BOLD_GREEN=''
    BOLD_YELLOW=''
    BOLD_BLUE=''
    # Reset color
    NC='' # No Color
fi
echo "${CYAN}███████╗██╗   ██╗███████╗███████╗███████╗██████╗"
echo "██╔════╝██║   ██║╚══███╔╝╚══███╔╝██╔════╝██╔══██╗"
echo "█████╗  ██║   ██║  ███╔╝   ███╔╝ █████╗  ██████╔╝"
echo "██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██╔══╝  ██╔══██╗"
echo "██║     ╚██████╔╝███████╗███████╗███████╗██║  ██║"
echo "╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝${NC}"

echo "\n${BOLD_BLUE}Welcome to the Fuzzer installation script.${NC}\n"
echo "${YELLOW}Please wait while we set up your environment.${NC}"

# Check the python version
if [ "$(python3 -c 'import sys; print(sys.version_info[0])')" -ne 3 ]; then
    echo "\n${BOLD_RED}Error: Python 3 is required to run this script.${NC}"
    exit 1
fi

# Check if virtualenv is installed
if ! [ -f .venv/bin/activate ]; then
    echo "\n${YELLOW}The virtual environment is not installed. Installing...${NC}"
    python3 -m venv .venv
    if [ $? -ne 0 ]; then
        echo "\n${BOLD_RED}Error: Failed to create virtual environment.${NC}"
        exit 1
    fi
else
    echo "\n${GREEN}The virtual environment is already installed.${NC}"
fi

# Source the virtualenv
. .venv/bin/activate
if [ $? -ne 0 ]; then
    echo "\n${BOLD_RED}Error: Failed to activate the virtual environment. Make sure .venv exists.${NC}"
    exit 1
fi

# Install the requirements
pip install -r requirements.txt > install.log 2>&1
if [ $? -ne 0 ]; then
    echo -e "\n${BOLD_RED}Error: Failed to install the requirements.${NC}"
    exit 1
fi

# Make the binaries executable
find /home/phill-lewis/tools/Fuzzer/target/ -type f -exec chmod +x {} \;

echo  "\n${BOLD_GREEN}Installation completed successfully!${NC}"
echo  "\n${CYAN}To begin using the virtual environment, run ${BOLD_YELLOW}'. .venv/bin/activate'${NC}"