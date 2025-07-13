import json

from flask import Blueprint, render_template, request, redirect, session
from scanner import Colors, write_in_log
from scanner import (Scanner, XSSVulnerability, SQLiVulnerability, CSRFVulnerability,
                     IDORVulnerability, CompositeDoSVulnerability, BSQLiVulnerability)

main = Blueprint('main', __name__)

c = Colors()


@main.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url')
        login = request.form.get('login')
        ignore = request.form.get('ignore').split(" ")
        scan_all = request.form.get('all')
        xss = request.form.get('xss')
        dxss = request.form.get('dxss')
        csrf = request.form.get('csrf')
        idor = request.form.get('idor')
        sqli = request.form.get('sqli')
        bsqli = request.form.get('bsqli')
        dos = request.form.get('dos')
        uname = request.form.get('uname')
        password = request.form.get('password')
        output = request.form.get('output')
        thread_value = request.form.get('thread')
        with_selenium = request.form.get('selenium')
        threads = int(thread_value) if thread_value else 5

        if url:
            print("url: " + url)
        if login:
            print(f"login url: {login}")
        if ignore[0]:
            print(f"ignor_url: {ignore}")
        if scan_all:
            print("all: " + scan_all)
        if xss:
            print("xss: " + xss)
        if dxss:
            print(f"dxss: {dxss}")
        if sqli:
            print("sqli: " + sqli)
        if bsqli:
            print(f"bsqli: {bsqli}")
        if csrf:
            print("csrf: " + csrf)
        if idor:
            print("idor: " + idor)
        if dos:
            print("dos: " + dos)
        if uname:
            print("uname: " + uname)
        if password:
            print("password: " + password)
        if output:
            print("output: " + output)
        if threads:
            print(f"threads: {threads}")
        if with_selenium:
            print(f"Selenium: {with_selenium}")

        if not url:
            return render_template('index.html', error="Please enter a URL.")

        if not ignore:
            ignore = None

        session['scan_data'] = {
            "url": url,
            "login": login,
            "ignore": ignore,
            "uname": uname,
            "password": password,
            "output": output,
            "threads": threads,
            "with_selenium": with_selenium,
            "dos": dos,
            "all": scan_all,
            "xss": xss,
            "dxss": dxss,
            "sqli": sqli,
            "bsqli": bsqli,
            "csrf": csrf,
            "idor": idor
        }
        return redirect('/scan')

    return render_template('index.html')


@main.route('/manual')
def manual():
    from flask import request
    form_html = request.args.get('form_html', '')
    action = request.args.get('form_action', '')
    method = request.args.get('form_method', '')
    payload = request.args.get('payload', '')
    return render_template('index.html', form_html=form_html, form_action=action, form_method=method, payload=payload)


@main.route("/scan")
def scan():
    data = session.get('scan_data')

    def run_scan(data):
        import json

        if not data:
            return

        scanner = Scanner(
            target_url=data["url"],
            ignored_urls=data["ignore"],
            threads=data["threads"]
        )

        scanner.log_path = "static/log.txt"
        with open(scanner.log_path, "w", encoding="utf-8") as log:
            log.write("🔍 Starting scan...\n")

        if data["uname"] and data["password"]:
            scanner.dynamic_login(data["url"], data["login"], data["uname"], data["password"])

        if data["dos"]:
            print(f"{c.warning('*******************DoS**********************')}")
            write_in_log(f"*******************DoS**********************")
            scanner.add_test(CompositeDoSVulnerability())
        else:
            if data["all"]:
                print(f"{c.warning('*******************ALL**********************')}")
                write_in_log(f"*******************ALL**********************")
                scanner.add_test(XSSVulnerability(use_dom=data["dxss"]))
                scanner.add_test(SQLiVulnerability())
                scanner.add_test(BSQLiVulnerability())
                scanner.add_test(CSRFVulnerability())
                scanner.add_test(IDORVulnerability())
            else:
                if data["xss"]:
                    print(f"{c.warning('*******************XSS**********************')}")
                    write_in_log(f"*******************XSS**********************")
                    scanner.add_test(XSSVulnerability(use_dom=False))

                if data["sqli"]:
                    print(f"{c.warning('*******************SQLi**********************')}")
                    write_in_log(f"*******************SQLi**********************")
                    scanner.add_test(SQLiVulnerability())
                elif data["bsqli"]:
                    print(f"{c.warning('*******************BSQLi**********************')}")
                    write_in_log(f"*******************BSQLi**********************")
                    scanner.add_test(BSQLiVulnerability())

                if data["csrf"]:
                    print(f"{c.warning('*******************CSRF**********************')}")
                    write_in_log(f"*******************CSRF**********************")
                    scanner.add_test(CSRFVulnerability())

                if data["idor"]:
                    print(f"{c.warning('*******************IDOR**********************')}")
                    write_in_log(f"*******************IDOR**********************")
                    scanner.add_test(IDORVulnerability())

        scanner.crawl(use_selenium=data["with_selenium"], max_depht=5)
        scanner.run_scanner()

        with open(scanner.log_path, "a", encoding="utf-8") as log:
            log.write("✅ Scan completed.\n")

        with open("static/results.json", "w", encoding="utf-8") as f:
            json.dump(scanner.reporter.results, f, indent=2, ensure_ascii=False)

    import threading
    t = threading.Thread(target=run_scan, args=(data,))
    t.start()

    return render_template("processing_stream.html")


@main.route('/report')
def report():
    try:
        with open("static/results.json", "r", encoding="utf-8") as f:
            results = json.load(f)
        data = session.get('scan_data')
        url = data["url"] if data else "Unknown"
        return render_template("report.html", results=results, url=url)
    except:
        return "There are no search results currently available."


@main.route("/logs")
def get_logs():
    try:
        with open("static/log.txt", "r", encoding="utf-8") as f:
            return f.read()
    except:
        return "Waiting for log..."
