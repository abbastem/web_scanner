#!user/bin/env python3

from scanner import (Scanner, XSSVulnerability, SQLiVulnerability, CSRFVulnerability,
                     IDORVulnerability, BSQLiVulnerability, main, Colors, CompositeDoSVulnerability)
import requests

session = requests.Session()

args = main()

scanner = Scanner(
        target_url=args.url,
        ignored_urls=args.ignore,
        login_username=args.uname,
        login_password=args.password,
        threads=args.threads,
        output_format=args.output
    )

c = Colors()
scanner.session = session

if args.uname and args.password:
    scanner.dynamic_login(args.url, args.login, args.uname, args.password)

if args.dos:
    print(f"{c.warning('*******************DoS**********************')}")
    scanner.add_test(CompositeDoSVulnerability())
else:
    if args.all:
        print(f"{c.warning('*******************ALL**********************')}")
        scanner.add_test(XSSVulnerability(use_dom=args.dxss))
        scanner.add_test(SQLiVulnerability())
        scanner.add_test(CSRFVulnerability())
        scanner.add_test(IDORVulnerability())
    else:
        if args.xss:
            print(f"{c.warning('*******************XSS**********************')}")
            scanner.add_test(XSSVulnerability(use_dom=args.dxss))

        if args.sqli:
            print(f"{c.warning('*******************SQLi**********************')}")
            scanner.add_test(SQLiVulnerability())
        elif args.bsqli:
            print(f"{c.warning('*******************BSQLi**********************')}")
            scanner.add_test(BSQLiVulnerability())

        if args.csrf:
            print(f"{c.warning('*******************CSRF**********************')}")
            scanner.add_test(CSRFVulnerability())

        if args.idor:
            print(f"{c.warning('*******************IDOR**********************')}")
            scanner.add_test(IDORVulnerability())


scanner.crawl(use_selenium=args.selenium)
scanner.run_scanner()
