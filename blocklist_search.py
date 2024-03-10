import requests
import re
from colorama import init, Fore

# Initialize colorama
init()

def check_domain_in_blocklist(source_url, target_domain):
    try:
        response = requests.get(source_url)
        response.raise_for_status()

        lines = [line.strip() for line in response.text.split('\n') if line.strip() and not line.startswith(('#', '!'))]

        # Initialize an empty list to store results
        results = []

        # More precise whole word matching with wrap-around and domain separator check
        pattern = rf"\b{target_domain}(?!\.\w+)"  # Negative lookahead with domain separator check
        for line in lines:
            match = re.search(pattern, line, flags=re.MULTILINE)
            if match:
                results.append(True)

        # Return the results list
        return results

    except requests.exceptions.RequestException as e:
        print(f"Error checking {source_url}: {e}")

    # Return an empty list if there's an error
    return []

def find_blocking_blocklists(target_domain, aio_sources, category_sources):
    blocking_aio_blocklists = []
    blocking_category_blocklists = []

    for name, source in aio_sources.items():
        if check_domain_in_blocklist(source, target_domain):
            blocking_aio_blocklists.append(name)

    for name, source in category_sources.items():
        if check_domain_in_blocklist(source, target_domain):
            blocking_category_blocklists.append(name)

    if blocking_aio_blocklists:
        print(Fore.CYAN + f"Domain '{target_domain}' found in the following blocklists:\n")
        for blocklist in blocking_aio_blocklists:
            print(Fore.CYAN + f" - {blocklist}\n")

    if blocking_category_blocklists:
        print(Fore.MAGENTA + f"Domain '{target_domain}' found in the following categories:\n")
        for blocklist in blocking_category_blocklists:
            print(Fore.MAGENTA + f" - {blocklist}\n")

    if not blocking_aio_blocklists and not blocking_category_blocklists:
        print(Fore.RED + f"Domain '{target_domain}' not found in any blocklists.")

    # Reset the text color to default
    print(Fore.RESET, end='')

if __name__ == "__main__":
    aio_blocklist_sources = {
        'Bog AIO List': 'https://raw.githubusercontent.com/KnightmareVIIVIIXC/AIO-Firebog-Blocklists/main/lists/aiofirebog.txt',
        'Blue AIO List': 'https://raw.githubusercontent.com/KnightmareVIIVIIXC/AIO-Firebog-Blocklists/main/lists/aiofirebogblue.txt',
        'Green AIO List': 'https://raw.githubusercontent.com/KnightmareVIIVIIXC/AIO-Firebog-Blocklists/main/lists/aiofireboggreen.txt',
    }

    category_blocklist_sources = {
        'Suspicious': 'https://raw.githubusercontent.com/KnightmareVIIVIIXC/AIO-Firebog-Blocklists/main/lists/firebogsus.txt',
        'Advertising': 'https://raw.githubusercontent.com/KnightmareVIIVIIXC/AIO-Firebog-Blocklists/main/lists/firebogad.txt',
        'Tracking': 'https://raw.githubusercontent.com/KnightmareVIIVIIXC/AIO-Firebog-Blocklists/main/lists/firebogtrack.txt',
        'Malicious': 'https://raw.githubusercontent.com/KnightmareVIIVIIXC/AIO-Firebog-Blocklists/main/lists/firebogmal.txt',
    }

    while True:
        target_domain = input("Enter a domain to find (or type 'exit' to close): ")

        if target_domain.lower() == 'exit':
            print("Exiting the script.")
            break

        if '.' not in target_domain or target_domain.startswith('.') or target_domain.endswith('.') or '..' in target_domain:
            print(Fore.YELLOW + "Invalid domain")
            print(Fore.RESET, end='')
            continue

        find_blocking_blocklists(target_domain, aio_blocklist_sources, category_blocklist_sources)
