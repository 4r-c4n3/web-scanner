import nmap
import requests
import ssl
import click
import socket
from bs4 import BeautifulSoup
from tabulate import tabulate
from colorama import Fore, Style

def scan_ports(target):
    print("Scanning Top Ports ...")
    target = target[8:]
    nm = nmap.PortScanner()
    scan = nm.scan(hosts=target, ports="1-50")

    port_services = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port, data in nm[host][proto].items():
                port_services.append((port, data['name'] if 'name' in data else 'Unknown'))
    return port_services

def check_title(target):
    try:
        response = requests.get(target)
        soup = BeautifulSoup(response.content, 'html.parser')
        title = soup.find('title').text
        return {"Website Title": f"{Fore.GREEN}Present{Style.RESET_ALL}" if title else f"{Fore.RED}Missing{Style.RESET_ALL}"}
    except requests.RequestException as e:
        return {"Website Title": f"{Fore.YELLOW}Error{Style.RESET_ALL}"}

def check_robots(target):
    try:
        response = requests.get(target + "/robots.txt")
        return {"Robots.txt File": f"{Fore.GREEN}Present{Style.RESET_ALL}" if response.status_code == 200 else f"{Fore.RED}Missing{Style.RESET_ALL}"}
    except requests.RequestException as e:
        return {"Robots.txt File": f"{Fore.YELLOW}Error{Style.RESET_ALL}"}

def check_favicon(target):
    try:
        response = requests.get(target + "/favicon.ico")
        return {"Favicon": f"{Fore.GREEN}Present{Style.RESET_ALL}" if response.status_code == 200 else f"{Fore.RED}Missing{Style.RESET_ALL}"}
    except requests.RequestException as e:
        return {"Favicon": f"{Fore.YELLOW}Error{Style.RESET_ALL}"}

def check_ssl(target):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.connect((target, 443))
            ssl_info = s.ssl_get_server_certificate()
            return {"SSL/TLS": f"{Fore.GREEN}Enabled{Style.RESET_ALL}" if ssl_info else f"{Fore.RED}Disabled{Style.RESET_ALL}"}
    except (ssl.SSLError, socket.error) as e:
        return {"SSL/TLS": f"{Fore.YELLOW}Error{Style.RESET_ALL}"}

def test_http_methods(target):
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE']
    results = {}
    for method in methods:
        try:
            response = requests.request(method, target)
            status_code = response.status_code
            if status_code == 200:
                results[method] = f"{Fore.GREEN}{status_code}{Style.RESET_ALL}"
            else:
                results[method] = f"{Fore.RED}{status_code}{Style.RESET_ALL}"
        except requests.RequestException as e:
            results[method] = f"{Fore.YELLOW}Error{Style.RESET_ALL}"
    return {"HTTP Methods": results}

def analyze_cors(target):
    try:
        response = requests.options(target)
        cors_headers = response.headers.get('Access-Control-Allow-Origin')
        return {"CORS Policy": f"{Fore.GREEN}{cors_headers}{Style.RESET_ALL}" if cors_headers else f"{Fore.RED}Not set{Style.RESET_ALL}"}
    except requests.RequestException as e:
        return {"CORS Policy": f"{Fore.YELLOW}Error{Style.RESET_ALL}"}

@click.command()
@click.argument("target", nargs=1, required=True)
@click.option("-p", "--ports", help="Scan for open ports", is_flag=True)
@click.option("-hm","--http-methods", help="Test various HTTP methods", is_flag=True)
@click.option("-o","--other", help="Check for other bugs", is_flag=True)
@click.option("-f","--full", help="Run all security checks", is_flag=True)
def scan_website(target, ports, http_methods, other,full):
    if full :
        ports = http_methods = other = True
    try:
        if not target.startswith("http"):
            target = f"https://{target}"

        if ports:
            port_services = scan_ports(target)
            if len(port_services) != 0:
                print(f"\n-- {Fore.CYAN}Port Scan Results{Style.RESET_ALL} --")
                print(tabulate(port_services, headers=[f"{Fore.CYAN}Port{Style.RESET_ALL}", f"{Fore.CYAN}Service{Style.RESET_ALL}"], tablefmt="grid"))
            else:
                print(f"\n{Fore.GREEN}No open ports found!{Style.RESET_ALL}")
        if http_methods:
            http_methods_results = test_http_methods(target)
            print(f"\n--- {Fore.CYAN}HTTP Method Test Results{Style.RESET_ALL} ---")
            print(tabulate(http_methods_results["HTTP Methods"].items(), headers=[f"{Fore.CYAN}HTTP Method{Style.RESET_ALL}", f"{Fore.CYAN}Status Code{Style.RESET_ALL}"], tablefmt="grid"))

        if other:
            other_results = {}
            other_results.update(check_title(target))
            other_results.update(check_robots(target))
            other_results.update(check_favicon(target))
            other_results.update(check_ssl(target))
            other_results.update(analyze_cors(target))

            print(f"\n--- {Fore.CYAN}Other Security Checks{Style.RESET_ALL} ---")
            print(tabulate(other_results.items(), headers=[f"{Fore.CYAN}Category{Style.RESET_ALL}", f"{Fore.CYAN}Result{Style.RESET_ALL}"], tablefmt="grid"))
        if ports == http_methods == other == False  :
            print("What to find ?")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    try:
        scan_website()
    except KeyboardInterrupt:
        print("\n Exiting Program !!!!")
