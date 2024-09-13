import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="csp-analyzer",
    version="0.1",
    author="Mark Dube",
    author_email="mjdube99@gmail.com",
    description="Content Security Policy (CSP) Analyzer. Just a wrapper for Google's website.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    install_requires=["BeautifulSoup4", "requests", "selenium", "colorama"],
    entry_points={"console_scripts": ["csp-analyzer=csp_analyzer.main:main"]},
)
