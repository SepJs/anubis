#!/bin/bash

# رنگ‌بندی هکری اسکریپت
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}[*] Starting Anubis Security Scanner Installer...${NC}"

# ۱. چک کردن دسترسی روت
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[-] ERROR: Please run this installer with sudo!${NC}"
  echo -e "${YELLOW}Example: sudo ./install.sh${NC}"
  exit 1
fi

# ۲. چک کردن اینکه آیا Go نصب هست یا نه
if ! command -v go &> /dev/null; then
    echo -e "${RED}[-] ERROR: Go (Golang) is not installed on this system.${NC}"
    echo -e "${YELLOW}[*] Attempting to install Go via apt...${NC}"
    apt-get update && apt-get install -y golang
    if [ $? -ne 0 ]; then
        echo -e "${RED}[-] Failed to install Go automatically. Please install Go manually and try again.${NC}"
        exit 1
    fi
fi

# ۳. مرتب کردن ماژول‌ها و کامپایل
echo -e "${CYAN}[*] Tidying Go modules and compiling production binary...${NC}"
cd "$(dirname "$0")"
go mod tidy
go build -o anubis ./cmd/anubis

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Compilation successful!${NC}"
else
    echo -e "${RED}[-] ERROR: Compilation failed. Check your Go environment.${NC}"
    exit 1
fi

# ۴. انتقال به باینری‌های لینوکس
echo -e "${CYAN}[*] Deploying binary to /usr/local/bin/anubis...${NC}"
cp anubis /usr/local/bin/anubis
chmod +x /usr/local/bin/anubis

# ۵. پایان موفقیت‌آمیز
echo -e "\n${GREEN}██████████████████████████████████████████████████${NC}"
echo -e "${GREEN}[+] Anubis has been successfully installed globally!${NC}"
echo -e "${CYAN}[*] Developer: Unknown Xrg${NC}"
echo -e "${YELLOW}[*] You can now run the scanner from anywhere using: ${GREEN}anubis${NC}"
echo -e "${GREEN}██████████████████████████████████████████████████${NC}\n"
