import argparse
from selenium import webdriver
from bs4 import BeautifulSoup
from time import sleep
from colorama import init, Fore, Style

parser = argparse.ArgumentParser("""csp-analyzer https://example.com""")
parser.add_argument("target", action="store", help="https://example.com")
args = parser.parse_args()

op = webdriver.ChromeOptions()
op.add_argument("headless")
driver = webdriver.Chrome(options=op)


def get_csp_info(target, sleep_time=2):
    try:
        driver.get(
            f"https://csp-evaluator.withgoogle.com/?csp={target}"
        )  # navigate to the webpage1

        # Now, you can capture the updated HTML
        sleep(int(sleep_time))
        updated_html = driver.page_source

        soup = BeautifulSoup(updated_html, "html.parser")
    except Exception as e:
        print("[-] No Content Security Policy on target site")
        quit()

    col_values = soup.find_all("div", {"class": "col value"})
    description_divs = soup.find("div", {"class": "directive"})
    description_tags = description_divs.find_all("li")

    data_tooltip_value_divs = soup.find_all("div", {"class": "col icon"})

    tooltip_texts = []
    for div in data_tooltip_value_divs:
        tooltip_text = div.get("data-tooltip")
        if tooltip_text is not None:
            tooltip_texts.append(tooltip_text)

    values = []
    for div in col_values:
        values.append(div.text.strip())

    descriptions = []
    for li in description_tags:
        descriptions.append(li.text.strip())
    return values, descriptions, tooltip_texts


def text_out(
    level: str, policy: str, vuln_info: str, severity="information", max_length: int = 0
) -> str:
    severity = severity.lower()

    init()

    colors = {
        "information": (Fore.BLUE, "+" + Style.RESET_ALL),
        "medium": (Fore.YELLOW),
        "possible medium": (Fore.LIGHTRED_EX),
        "high": (Fore.RED),
        "possible high": (Fore.LIGHTRED_EX),
        "syntax error": (Fore.MAGENTA),
    }

    color = colors[severity]

    output: str = (
        f"[{color}+{Style.RESET_ALL}] "
        + color
        + level.ljust(7)
        + Style.RESET_ALL
        + "|".ljust(3)
        + policy.ljust(max_length)  # adjust width as needed
        + Style.RESET_ALL
        + " |".ljust(3)
        + vuln_info.ljust(20)  # adjust width as needed
    )
    return output


def main():
    print("[+] Getting CSP information...\n")

    try:
        # This could error out depending on connection to site
        values, descriptions, tooltip_texts = get_csp_info(args.target)
    except Exception as e:
        try:
            print("[-] Trying longer sleep time...")
            values, descriptions, tooltip_texts = get_csp_info(
                args.target, sleep_time=5
            )
        except Exception as e:
            print("[-] Likely could not connect to site...", e)
            quit()

    # start total counter
    total = 0

    length = len(max(values, key=len))
    csp_values = {}
    csp_values["High"] = []
    csp_values["Medium"] = []

    severity_mapping = {
        "high": ("High", "High"),
        "medium": (
            "Medium",
            "Medium",
        ),
    }

    for count, tooltip in enumerate(tooltip_texts):
        total = total + 1

        tooltip = tooltip.lower()
        for severity, (label, level) in severity_mapping.items():
            if severity in tooltip:
                # Group values and descriptions by severity
                csp_values[label].append((values[count], descriptions[count]))

        if total == len(values):
            break

    # Print grouped data
    for severity, group in csp_values.items():
        for value, description in group:
            print(
                text_out(
                    severity, value, description, severity=severity, max_length=length
                )
            )

    driver.quit()  # close the browser instance


if __name__ == "__main__":
    main()
