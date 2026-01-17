#!/usr/bin/env python3

import os
import sys
import subprocess
import shutil

# ===================== BANNER ===================== #

BANNER = r"""
    ___        __        ____                 
   /   | _____/ /_____ _/ __ \___  _________ 
  / /| |/ ___/ __/ __ `/ /_/ / _ \/ ___/ __ \
 / ___ / /__/ /_/ /_/ / _, _/  __/ /__/ /_/ /
/_/  |_\___/\__/\__,_/_/ |_|\___/\___/\____/

        AutoxRecon Framework
        Automated Web Reconnaissance
        Type 'help' to get help
        Type 'scan example.com' to get scan the domain
"""
# ===================== TOOL LISTS ===================== #

APT_TOOLS = [
    "nmap",
    "subfinder",
    "amass",
    "eyewitness",
    "dnsutils",
    "whois",
    "jq",
    "curl",
    "wget",
    "git",
    "arjun"
]

GO_TOOLS = {
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "httprobe": "github.com/tomnomnom/httprobe@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "subjack": "github.com/haccer/subjack@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest"
}



# ===================== UTILS ===================== #

def run(cmd, output=None):
    if output:
        with open(output, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL)
    else:
        subprocess.run(cmd, stderr=subprocess.DEVNULL)

# ===================== INSTALLERS ===================== #

def install_go():
    if shutil.which("go"):
        return

    print("\n[!] Go not found")
    choice = input("Install Go (golang-go) now? (y/N): ").lower()
    if choice != "y":
        print("[!] Go is required. Exiting.")
        sys.exit(1)

    subprocess.run(["sudo", "apt", "update"], check=True)
    subprocess.run(["sudo", "apt", "install", "-y", "golang-go"], check=True)

    print("[+] Go installed successfully")
    print("[!] Ensure $GOPATH/bin is in PATH\n")

def install_tools():
    install_go()

    print("\n[+] Installing APT tools...")
    subprocess.run(["sudo", "apt", "update"], stdout=subprocess.DEVNULL)
    subprocess.run(
        ["sudo", "apt", "install", "-y"] + APT_TOOLS,
        check=True
    )

    print("\n[+] Installing Go-based tools...")
    for tool, repo in GO_TOOLS.items():
        print(f"[+] Installing {tool}")
        subprocess.run(["go", "install", repo], check=True)

    print("\n[+] All tools installed successfully")
    print("[!] Restart terminal or ensure PATH is updated\n")

def check_dependencies(auto_install=False):
    missing = []

    # check APT + Go tools only
    for tool in APT_TOOLS + list(GO_TOOLS.keys()):
        if shutil.which(tool) is None:
            missing.append(tool)

    if not missing:
        print("[+] All required tools installed")
        return

    print("\n[!] Missing tools detected:")
    for tool in missing:
        print(f"   - {tool}")

    if not auto_install:
        choice = input("\nInstall missing tools now? (y/N): ").lower()
        if choice != "y":
            print("[!] Cannot continue without dependencies")
            return

    install_tools()

def ensure_go_path():
    go_bin = os.path.expanduser("~/go/bin")
    path = os.environ.get("PATH", "")
    if go_bin not in path:
        os.environ["PATH"] = f"{go_bin}:{path}"

# ===================== DIRECTORY STRUCTURE ===================== #

def create_dirs(base):
    paths = [
        # classic recon
        "recon/scans",
        "recon/httprobe",
        "recon/potential_takeovers",
        "recon/wayback/params",
        "recon/wayback/extensions",

        # advanced recon
        "subdomains/alive",
        "subdomains/katana",
        "subdomains/arjun",
        "subdomains/wayback",
        "subdomains/eyewitness",
        "subdomains/scans",
        "subdomains/reports"
    ]

    for p in paths:
        os.makedirs(os.path.join(base, p), exist_ok=True)

# ===================== RECON MODULES ===================== #

def subdomain_enum(domain, base):
    print("[+] Enumerating subdomains")
    run(["assetfinder", domain], f"{base}/recon/final.txt")

def alive_hosts(base):
    print("[+] Probing alive hosts")
    cmd = f"cat {base}/recon/final.txt | httprobe -s -p https:443 | sed 's~https\\?://~~' | tr -d ':443'"
    run(["bash", "-c", cmd], f"{base}/subdomains/alive/alive.txt")

def katana_scan(base):
    print("[+] Running Katana")
    run([
        "katana",
        "-list", f"{base}/subdomains/alive/alive.txt",
        "-o", f"{base}/subdomains/katana/endpoints.txt"
    ])

def wayback_scan(base):
    print("[+] Fetching Wayback URLs")
    cmd = f"cat {base}/recon/final.txt | waybackurls"
    run(["bash", "-c", cmd], f"{base}/subdomains/wayback/urls.txt")

def arjun_scan(base):
    print("[+] Running Arjun")
    run([
        "arjun",
        "-i", f"{base}/subdomains/katana/endpoints.txt",
        "-oJ", f"{base}/subdomains/arjun/params.json"
    ])

def eyewitness_scan(base):
    print("[+] Running EyeWitness")
    run([
        "eyewitness",
        "--web",
        "-f", f"{base}/subdomains/alive/alive.txt",
        "-d", f"{base}/subdomains/eyewitness"
    ])

def takeover_scan(base):
    print("[+] Checking subdomain takeovers")
    run([
        "subjack",
        "-w", f"{base}/recon/final.txt",
        "-ssl",
        "-timeout", "30",
        "-o", f"{base}/recon/potential_takeovers/results.txt"
    ])

def nmap_scan(base):
    print("[+] Running Nmap")
    run([
        "nmap",
        "-iL", f"{base}/subdomains/alive/alive.txt",
        "-T4",
        "-oA", f"{base}/recon/scans/nmap"
    ])

# ===================== SCAN CONTROLLER ===================== #

def start_scan(domain):
    base = f"targets/{domain}"

    print(f"\n[+] Starting recon on {domain}")
    print(f"[+] Output directory: {base}\n")

    check_dependencies(auto_install=False)
    create_dirs(base)

    subdomain_enum(domain, base)
    alive_hosts(base)
    katana_scan(base)
    wayback_scan(base)
    arjun_scan(base)
    eyewitness_scan(base)
    takeover_scan(base)
    nmap_scan(base)

    print(f"\n[+] Recon completed for {domain}\n")

# ===================== HELP ===================== #

def show_help():
    print("""
Available Commands
------------------
 help                    Show this help menu
 scan <domain>           Run full reconnaissance
 install                 Install missing tools
 clear                   Clear the screen
 exit / quit             Exit AutoxRecon

Example:
 scan example.com
""")

# ===================== INTERACTIVE SHELL ===================== #

def interactive_shell():
    ensure_go_path()
    os.system("clear")
    print(BANNER)

    while True:
        try:
            cmd = input("AutoxRecon > ").strip()

            if not cmd:
                continue

            if cmd in ("exit", "quit"):
                print("[*] Exiting AutoxRecon")
                break

            elif cmd == "help":
                show_help()

            elif cmd == "clear":
                os.system("clear")
                print(BANNER)

            elif cmd == "install":
                check_dependencies(auto_install=True)

            elif cmd.startswith("scan "):
                domain = cmd.split(" ", 1)[1].strip()
                if domain:
                    start_scan(domain)
                else:
                    print("[!] Please provide a domain")

            else:
                print("[!] Unknown command. Type 'help'")

        except KeyboardInterrupt:
            print("\n[*] Use 'exit' to quit")

# ===================== MAIN ===================== #

def main():
    interactive_shell()

if __name__ == "__main__":
    main()

