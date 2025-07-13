#!user/bin/env python3
import tempfile
import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import argparse
import json
from datetime import datetime
from PIL import Image
from urllib.parse import urlparse, parse_qs, urlencode
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from jinja2 import Environment, FileSystemLoader
import time
import threading
from tools.slowloris_runner import SlowlorisAttack
from difflib import SequenceMatcher


def export_html_report(results, filename="report.html"):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("template.html")
    output = template.render(scan_date=datetime.now(), result=results)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(output)


def write_in_log(result):
    with open("static/log.txt", "a", encoding="utf-8") as log:
        log.write(result + "\n")


def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()


class Colors:
    def __init__(self):
        self.GREEN = "\033[92m"
        self.YELLOW = "\033[93m"
        self.RED = "\033[91m"
        self.BLUE = "\033[94m"
        self.GRAY = "\033[90m"
        self.RESET = "\033[0m"

    def success(self, x):
        return f"{self.GREEN}{x}{self.RESET}"

    def info(self, x):
        return f"{self.BLUE}{x}{self.RESET}"

    def warning(self, x):
        return f"{self.YELLOW}{x}{self.RESET}"

    def error(self, x):
        return f"{self.RED}{x}{self.RESET}"


def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--login", help="Login URL (e.g /login.php)")
    parser.add_argument("--ignore", nargs='*', default=[], help="URLs to ignore (e.g /logout.php)")

    parser.add_argument("--xss", action="store_true", help="Enable XSS testing")
    parser.add_argument("--dxss", action="store_true", help="Enable Dome XSS testing")
    parser.add_argument("--sqli", action="store_true", help="Enable SQLi testing")
    parser.add_argument("--bsqli", action="store_true", help="Enable Time Based SQLi testing")
    parser.add_argument("--csrf", action="store_true", help="Enable CSRF testing")
    parser.add_argument("--idor", action="store_true", help="Enable IDOR testing")
    parser.add_argument("--dos", action="store_true", help="Enable DoS testing")
    parser.add_argument("--all", action="store_true", help="Enable all testing")

    parser.add_argument("--selenium", action="store_true", help="Enable use selenium")

    parser.add_argument("--uname", help="Login username")
    parser.add_argument("--password", help="Login password")

    parser.add_argument("--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("--output", choices=["json", "html"], default="json", help="Output format")

    return parser.parse_args()


def assess_severity(vuln_type):
    if "SQLi" in vuln_type:
        return "High"
    elif "XSS" in vuln_type:
        return "Medium"
    elif "CSRF" in vuln_type:
        return "Low"
    else:
        return "Info"


def load_payload(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]


def init_driver():
    from selenium import webdriver
    from selenium.webdriver.firefox.service import Service
    from selenium.webdriver.firefox.options import Options
    from webdriver_manager.firefox import GeckoDriverManager

    options = Options()
    options.add_argument("--headless")
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")

    # Solution to the problem of creating a temporary folder for each thread session
    user_data_dir = tempfile.mkdtemp()
    options.set_preference("browser.download.folderList", 2)
    options.set_preference("browser.download.dir", user_data_dir)

    driver = webdriver.Firefox(service=Service(GeckoDriverManager().install()), options=options)
    return driver


class VulnerabilityTest:
    def __init__(self):
        self.c = Colors()

    def test_form(self, form, url, submit_function, get_website):
        raise NotImplementedError

    def test_link(self, url, session):
        raise NotImplementedError


def test_dom_xss(url, pyload):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")

        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        source = driver.page_source
        driver.quit()

        return "xss_test" in source
    except:
        return False


class XSSVulnerability(VulnerabilityTest):
    def __init__(self, use_dom=False):
        super().__init__()
        self.use_dom = use_dom
        self.xss_payloads = load_payload("payloads/xss_payloads.txt")

    def test_form(self, form, url, submit_function, get_website):
        for payload in self.xss_payloads:
            response = submit_function(form, payload, url)
            if payload.lower() in response.text.lower():
                if "<script>" in response.text or "onerror=" in response.text:
                    print(f"{self.c.success('[+++]')} XSS Detected in form with payload: {self.c.success(payload)}")
                    write_in_log(f"[+++] XSS Detected in form with payload: {payload}")
                    return {
                        "found": True,
                        "payload": payload,
                        "evidence": str(form),
                        "type": "Reflected XSS"
                    }
        return {"found": False}

    def test_link(self, url, session):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return {"found": False}

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in params:
            for payload in self.xss_payloads:
                # Inject payload
                test_params = params.copy()
                test_params[param] = payload
                full_url = base + "?" + urlencode(test_params, doseq=True)

                try:
                    response = session.get(full_url, timeout=5)
                    if payload.lower() in response.text.lower():
                        if "<script>" in response.text or "onerror=" in response.text:
                            print(
                                f"{self.c.success('[+++]')} XSS Detected in URL with payload: {self.c.success(payload)}")
                            write_in_log(f"[+++] XSS Detected in URL with payload: {payload}")
                            return {
                                "found": True,
                                "payload": payload,
                                "param": param,
                                "evidence": response.text[:300],
                                "type": "Reflected XSS"
                            }

                    # DOM-based check
                    if self.use_dom and test_dom_xss(full_url, payload):
                        print(
                            f"{self.c.success('[+++]')} DOM-based XSS Detected with payload: {self.c.success(payload)}")
                        write_in_log(f"[+++] DOM-based XSS Detected with payload: {payload}")
                        return {
                            "found": True,
                            "payload": payload,
                            "param": param,
                            "evidence": full_url,
                            "type": "DOM XSS"
                        }

                except Exception as e:
                    continue

        return {"found": False}


class SQLiVulnerability(VulnerabilityTest):
    payloads = load_payload("payloads/sqli_payloads.txt")

    def test_form(self, form, url, submit_function, get_website):
        for payload in self.payloads:
            response = submit_function(form, payload, url)
            response_without_p = get_website(url)

            if "SQL" in response.text or "syntax" in response.text or response_without_p != response:
                print(f"{self.c.success('[+++]')} SQLi Detected with payload: {self.c.success(payload)}")
                write_in_log(f"[+++] SQLi Detected with payload: {payload}")
                return {
                    "found": True,
                    "payload": payload,
                    "evidence": str(form)
                }
        return {"found": False}

    def test_link(self, url, session):
        for payload in self.payloads:
            if "=" not in url:
                continue
            test_url = url.replace("=", "=" + payload)
            response = session.get(test_url)

            if "SQL" in response.text or "syntax" in response.text:
                print(f"{self.c.success('[+++]')} SQLi Detected in URL with payload: {self.c.success(payload)}")
                write_in_log(f"[+++] SQLi Detected in URL with payload: {payload}")
                return {
                    "found": True,
                    "payload": payload,
                    "evidence": response.text[:300]
                }
        return {"found": False}


class BSQLiVulnerability(VulnerabilityTest):
    def __init__(self):
        super().__init__()
        self.delay_payload = "1' OR SLEEP(5)-- -"

    def test_link(self, url, session):
        from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
        print(f"{self.c.info('[*]')} Testing Blind SQLi on {url}")
        write_in_log(f"[*] Testing Blind SQLi on {url}")

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param in params:
            test_params = params.copy()
            test_params[param] = self.delay_payload

            query_string = urlencode(test_params, doseq=True)
            new_url = urlunparse((parsed.scheme, param.netloc, parsed.path, '', query_string, ''))

            try:
                start = time.time()
                response = session.get(new_url, timeout=10)
                end = time.time() - start

                elapsed = end - start
                print(f"[%] Elapsed URL time: {elapsed:.2f} seconds")

                if elapsed > 4:
                    print(f"{self.c.success('[+++]')} Potential Blind SQLi on parameter: {param}"
                          f"(Response time: {elapsed:.2f}s")
                    write_in_log(f"[+++] Potential Blind SQLi on parameter: {param} (Response time: {elapsed:.2f}s")
                    return {
                        "found": True,
                        "payload": self.delay_payload + " Response time: " + str(int(elapsed)) + "s",
                        "evidence": response.text[:300]
                    }
            except requests.exceptions.Timeout:
                print(f"{self.c.warning('[!]')} Timeout occurred on {url} with parameter {param}")
                write_in_log(f"[!] Timeout occurred on {url} with parameter {param}")
            except Exception as e:
                print(f"{self.c.error('[!]')} Error testing parameter {param}: {e}")
                write_in_log(f"[!] Error testing parameter {param}: {e}")

        return {"found": False}

    def test_form(self, form, url, submit_function, get_website):
        print(f"{self.c.info('[*]')} Testing Blind SQLi Form on {url}")
        write_in_log(f"[*] Testing Blind SQLi Form on {url}")

        try:
            start = time.time()
            response = submit_function(form, self.delay_payload, url)
            end = time.time()

            elapsed = end - start
            print(f"[%] Elapsed FORM time: {elapsed:.2f} seconds")
            write_in_log(f"[%] Elapsed FORM time: {elapsed:.2f} seconds")

            if elapsed > 4:
                print(f"{self.c.success('[+++]')} Potential Blind SQLi in form (Response time: {elapsed:.2f}s")
                write_in_log(f"[+++] Potential Blind SQLi in form (Response time: {elapsed:.2f}s")
                return {
                    "found": True,
                    "payload": self.delay_payload + " Response time: " + str(int(elapsed)) + "s",
                    "evidence": str(form)
                }
        except requests.exceptions.Timeout:
            print(f"{self.c.warning('[!]')} Timeout occurred on {form} with parameter {self.delay_payload}")
            write_in_log(f"[!] Timeout occurred on {form} with parameter {self.delay_payload}")
        except Exception as e:
            print(f"{self.c.error('[!]')} Error testing parameter {self.delay_payload}: {e}")
            write_in_log(f"[!] Error testing parameter {self.delay_payload}: {e}")

        return {"found": False}


class CSRFVulnerability(VulnerabilityTest):
    def test_form(self, form, url, submit_function, get_website):
        inputs = form.find_all("input")
        form_data = {}

        csrf_field = None
        for html_input in inputs:
            name = html_input.get("name")
            value = html_input.get("value", "test")
            if name:
                form_data[name] = value
                if "csrf" in name.lower():
                    csrf_field = name

        try:
            r1 = submit_function(form, form_data, url)
        except:
            return {"found": False}

        if csrf_field:
            fake_data = form_data.copy()
            fake_data[csrf_field] = "invalid_token"
            try:
                r2 = submit_function(form, fake_data, url)
            except:
                return {"found": False}

            if r1.status_code == r2.status_code and r1.text.strip() == r2.text.strip():
                return {
                    "found": True,
                    "payload": f"CSRF bypassed by injecting invalid token in {csrf_field}",
                    "evidence": "Response unchanged after token manipulation"
                }

        else:
            return {
                "found": True,
                "payload": "Form lacks CSRF token",
                "evidence": "No input with name including 'csrf'"
            }

        return {"found": False}

    def test_link(self, url, session):
        if "=" in url and ("delete" in url.lower() or "remove" in url.lower()):
            print(f"{self.c.info('[*]')} Testing URL for CSRF via GET method: {url}")
            response = session.get(url)
            if response.status_code == 200:
                print(f"{self.c.success('[+++]')} Warning:  Possible CSRF via GET request at {url}")
                return {
                    "found": True,
                    "payload": None,
                    "evidence": response.text[:300]
                }
        return {"found": False}


class IDORVulnerability(VulnerabilityTest):
    def test_link(self, url, session):
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return {"found": False}

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in params:
            original_value = params[param][0]
            test_params = params.copy()

            try:
                r_orig = session.get(url)
            except:
                continue

            base_text = r_orig.text.strip()

            for test_id in range(1, 21):
                if str(test_id) == original_value:
                    continue

                test_params[param] = str(test_id)
                test_url = base + "?" + urlencode(test_params, doseq=True)

                try:
                    r = session.get(test_url)
                    if r.status_code == 200:
                        diff_ratio = similarity(base_text, r.text.strip())
                        if diff_ratio < 0.85:
                            return {
                                "found": True,
                                "param": param,
                                "payload": f"{param}={test_id}",
                                "evidence": f"Response significantly different for id={test_id}"
                            }
                except:
                    continue

        return {"found": False}

    def test_form(self, form, url, submit_function, get_website):
        return {"found": False}  # Usually IDOR is via direct link access


class DoSVulnerability(VulnerabilityTest):
    def test_link(self, url, session):
        def flood():
            try:
                for _ in range(50):
                    session.get(url)
            except:
                pass

        start = time.time()
        threads = [threading.Thread(target=flood) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        duration = time.time() - start

        if duration > 10:
            print(f"{self.c.warning('[Dos]')} Potential DoS at {url} - response time {duration:.2f}s")
            write_in_log(f"[DoS] Potential DoS at {url} - response time {duration:.2f}s")
            return {
                "found": True,
                "payload": "flooded GET requests",
                "evidence": f"Response time: {duration:.2f} sec for 1000 requests"
            }
        return {"found": False}

    def test_form(self, form, url, submit_function, get_website):
        import time
        import threading

        def flood():
            for _ in range(200):
                try:
                    submit_function(form, "dos_test", url)
                except:
                    pass

        threads = [threading.Thread(target=flood) for _ in range(20)]

        start = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        end = time.time()
        duration = end - start

        if duration > 10:
            print(f"{self.c.warning('[DoS]')} Possible DoS: {duration:.2f} seconds")
            write_in_log(f"[DoS] Possible DoS: {duration:.2f} seconds")
            return {
                "found": True,
                "payload": "flooding form requests",
                "evidence": f"Form {url} responded slowly: {duration:.2f}s"
            }

        return {"found": False}


class SlowlorisDoSVulnerability(VulnerabilityTest):
    def test_link(self, url, session):
        print(f"{self.c.warning('[*]')} Launching Slowloris DoS test on: {url}")
        write_in_log(f"[*] Launching Slowloris DoS test on: {url}")
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        try:
            start = time.time()
            session.get(url, timeout=5)
            base_time = time.time() - start
        except:
            base_time = None

        attacker = SlowlorisAttack(host, port=port, sockets_count=100)
        attacker.run(duration=20)

        try:
            start = time.time()
            session.get(url, timeout=5)
            attacked_time = time.time() - start
        except:
            attacked_time = 10

        if base_time is not None and attacked_time > base_time + 3:
            print(f"{self.c.success('[+++]')} Slowloris DoS likely succeeded at {url}")
            write_in_log(f"[***] Slowloris DoS likely succeeded at {url}")
            return {
                "found": True,
                "payload": "Slowloris attack",
                "evidence": f"Baseline: {base_time:.2f}s, After: {attacked_time:.2f}s"
            }

        return {"found": False}

    def test_form(self, form, url, submit_function, get_website):
        return {"found": False}


class CompositeDoSVulnerability(VulnerabilityTest):
    def __init__(self):
        super().__init__()
        self.methods = [
            DoSVulnerability(),
            SlowlorisDoSVulnerability()
        ]

    def test_link(self, url, session):
        for method in self.methods:
            result = method.test_link(url, session)
            if result.get("found"):
                result["type"] = type(method).name
                return result
        return {"found": False}

    def test_form(self, form, url, submit_function, get_website):
        for method in self.methods:
            result = method.test_form(form, url, submit_function)
            if result.get("found"):
                result["type"] = type(method).name
                return result
        return {"found": False}


class FuzzingVulnerability(VulnerabilityTest):
    def test_link(self, url, session):
        test_params = ["admin", "debug", "test", "id", "user", "ref", "page", "token"]
        parsed = urlparse(url)

        if not parsed.path or parsed.path == "/":
            return {"found": False}

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in test_params:
            test_url = base + "?" + urlencode({param: "test"})

            try:
                r = session.get(test_url)
                text = r.text.lower()
                if any(word in text for word in ["error", "admin", "debug", "unauthorized", "exception"]):
                    return {
                        "found": True,
                        "payload": f"{param}=test",
                        "type": "Fuzzing discovery",
                        "evidence": f"Response contains keywords for param: {param}"
                    }
            except:
                continue

        return {"found": False}

    def test_form(self, form, url, submit_function, get_website):
        return {"found": False}


class Scanner:
    def __init__(self, target_url, ignored_urls=None, login_username=None,
                 login_password=None, threads=5, output_format="json"):
        self.target_url = target_url
        self.ignored_urls = ignored_urls or [target_url + "/logout.php"]
        self.username = login_username
        self.password = login_password
        self.threads = threads
        self.output_format = output_format
        self.tests = []
        self.links = set()
        self.session = requests.Session()
        self.reporter = ReportLogger()
        self.c = Colors()

    def add_test(self, test_obj):
        self.tests.append(test_obj)

    def dynamic_login(self, base_url, login_url, username, password):
        response = self.session.get(login_url)
        soup = BeautifulSoup(response.text, "html.parser")

        form = soup.find("form")
        if not form:
            print(f"{self.c.error('[!]')} No login form found on the page.")
            write_in_log(f"[!] No login form found on the page.")
            return False

        post_data = {}

        for input_tag in form.find_all("input"):
            name = input_tag.get("name")
            if not name:
                continue

            value = input_tag.get('value', '')

            if "username" in name.lower():
                post_data[name] = username
            elif "pass" in name.lower():
                post_data[name] = password
            else:
                post_data[name] = value

        action = form.get('action')
        post_url = urljoin(base_url, action)

        method = form.get('method', 'post').lower()
        if method == "post":
            result = self.session.post(post_url, data=post_data)
        else:
            result = self.session.get(post_url, data=post_data)

        if "logout" in result.text.lower() or "dashboard" in result.text.lower():
            print(f"{self.c.success('[+]')} Login ok")
            write_in_log(f"[*] Login ok")
            return True
        else:
            print(f"{self.c.error('[-]')} Login error")
            write_in_log(f"[-] Login error")
            return False

    def href_content(self, url):
        try:
            response = self.session.get(url, timeout=5)
            if "text/html" not in response.headers.get("Content-Type", ""):
                return []

            soup = BeautifulSoup(response.text, 'html.parser')
        except Exception as e:
            print(f"{self.c.error('[-]')} Error in this page: {e}")
            write_in_log(f"[-] Error in this page: {e}")
            return []

        urls = set()
        for a in soup.find_all('a', href=True):
            href = urljoin(url, a['href'])
            if any(href.endswith(ext) for ext in ['.jpg', '.png', '.css', '.js']):
                continue
            urls.add(href)

        for tag in soup.find_all('form'):
            action = tag.get('action')
            if action:
                urls.add(urljoin(url, action))

        js_links = re.findall(r"""(?:"|')((?:\/|\.)[^"']+\.(php|html|asp|aspx|jsp)[^"']*)(?:"|')""", response.text)
        for match in js_links:
            link = match[0]
            urls.add(urljoin(url, link))

        return list(urls)

    def without_selenium_crawl(self):
        visited = set()
        queue = deque([self.target_url])

        number_of_links = 0
        while queue:
            current_url = queue.popleft()
            if current_url in visited or any(ig in current_url for ig in self.ignored_urls):
                continue

            visited.add(current_url)
            print(f"{self.c.warning('[*]')} Crawling: {current_url}")
            write_in_log(f"[*] Crawling: {current_url}")

            number_of_links += 1
            self.links.update([current_url])

            for link in self.href_content(current_url):
                if self.target_url in link and link not in visited:
                    queue.append(link)
        print(self.c.success(f"{self.c.info('[***]')}Total number of links: {number_of_links}"))
        write_in_log(f"[***] Total number of links: {number_of_links}")

    def crawl(self, use_selenium=False, max_depht=2):
        print(f"{self.c.info('[*]')} Starting crawling process...")
        write_in_log("[*] Starting crawling process...")
        if use_selenium:
            links, _ = self.selenium_crawl(max_depht)
            self.links.update([links])
        else:
            self.without_selenium_crawl()

    def selenium_crawl(self, max_depht=2):
        print(f"{self.c.info('[*]')} Using Selenium for dynamic crawling...")
        write_in_log("[*] Using Selenium for dynamic crawling...")
        visited = set()
        to_visit = [self.target_url]
        all_links = set()
        depht = 0

        while to_visit and depht < max_depht:
            current_level = to_visit.copy()
            to_visit.clear()
            depht += 1

            for url in current_level:
                if url in visited or any(ig in url for ig in self.ignored_urls):
                    continue
                print(f"{self.c.warning('[+]')} Crawling: {url}")
                write_in_log(f"[+] Crawling: {url}")
                try:
                    driver = init_driver()
                    driver.get(url)
                    time.sleep(2)
                    soup = BeautifulSoup(driver.page_source, 'html.parser')
                    visited.add(url)

                    for a in soup.find_all("a", href=True):
                        href = a['href']
                        link = urljoin(url, href)

                        if self.target_url in link and link not in visited:
                            to_visit.append(link)
                            all_links.add(link)

                    driver.quit()
                except Exception as e:
                    print(f"{self.c.error('[!]')} Error crawling {url}, {e}")
                    write_in_log(f"[!] Error crawling {url}, {e}")
                    continue

        print(f"[+++] Finished crawling. Found {len(all_links)} total links.")
        write_in_log(f"[+++] Finished crawling. Found {len(all_links)} total links.")
        return list(all_links), []  # Later, models may also be supported

    def extract_forms(self, url):
        response = self.session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.find_all('form')

    def submit_form(self, form, static_value, url):
        action = form.get('action')
        if action == "#":
            action = url
            post_url = action
        else:
            post_url = urljoin(url, action)

        if "?_method=put" in post_url.lower():
            method = "put"
        elif "?_method=delete" in post_url.lower():
            method = "delete"
        else:
            method = form.get('method', 'get').lower()

        post_data = {}

        for input_tag in form.find_all('input'):
            input_type = input_tag.get('type')
            name = input_tag.get('name')
            value = input_tag.get('value')

            if not name:
                continue

            if input_type in ['text', 'search', 'email', 'url']:
                post_data[name] = static_value
            elif input_type == "file":
                post_data[name] = Image.open("static/Screenshot from 2024-12-04 09-42-22.png")
            elif input_type in ['hidden', 'submit', 'button']:
                post_data[name] = value
            elif input_type in ['checkbox', 'radio']:
                if input_tag.has_attr('checked'):
                    post_data[name] = value
            else:
                post_data[name] = static_value

        for textarea in form.find_all('textarea'):
            name = textarea.get('name')
            if name:
                post_data[name] = static_value

        for select in form.find_all('select'):
            name = select.get('name')
            if not name:
                continue
            option = select.find_all('option')
            if option:
                post_data[name] = option[0].get('value', '')

        print(f"{self.c.warning('[^^^]')} post url: {post_url}")
        print(f"{self.c.warning('[^^^]')} post data: {post_data}")
        print(f"method: {method}")

        if method == "post":
            return self.session.post(post_url, data=post_data)
        elif method == "delete":
            return self.session.delete(post_url, data=post_data)
        elif method == "put":
            return self.session.put(post_url, data=post_data)
        else:
            return self.session.get(post_url, params=post_data)

    def _scan_single_link(self, link):
        for form in self.extract_forms(link):
            for test in self.tests:
                print(f"{self.c.info('[*]')} Testing form on {link} with {type(test).__name__}")
                write_in_log(f"[+] Testing form on {link} with {type(test).__name__}")

                result = test.test_form(form, link, self.submit_form, self.get_web_sit)
                if result.get("found"):
                    self.reporter.log({
                        "type": type(test).__name__,
                        "location": link,
                        "method": "form",
                        "payload": result.get("payload"),
                        "severity": assess_severity(type(test).__name__),
                        "evidence": result.get("evidence")
                    })

        for test in self.tests:
            if "=" in link:
                print(f"{self.c.info('[*]')} Testing link: {link}")
                write_in_log(f"[*] Testing link: {link}")
                result = test.test_link(link, self.session)
                if isinstance(result, dict) and result.get("found"):
                    self.reporter.log({
                        "type": type(test).__name__,
                        "location": link,
                        "method": "url",
                        "payload": result.get("payload"),
                        "severity": assess_severity(type(test).__name__),
                        "evidence": result.get("evidence")
                    })

    def run_scanner(self):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self._scan_single_link, self.links)

        if self.output_format == "html":
            export_html_report(self.reporter.results)

        self.reporter.save()

    def get_web_sit(self, url):
        return self.session.get(url)


class ReportLogger:
    def __init__(self, file_name="report.json"):
        self.file_name = file_name
        self.results = []
        self.c = Colors()

    def log(self, entry):
        self.results.append(entry)

    def save(self):
        report = {
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "result": self.results
        }
        with open(self.file_name, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

        print(self.c.success(f"[+] {len(self.results)} vulnerabilities found"))
        write_in_log(f"[+] {len(self.results)} vulnerabilities found")
        vuln_types = {}
        for item in self.results:
            vuln_types[item['type']] = vuln_types.get(item['type'], 0) + 1
        for vtype, count in vuln_types.items():
            print(f" - {vtype}: {count}")
            write_in_log(f" - {vtype}: {count}")
