from setuptools import setup, find_packages

with open("requirements.txt") as f:
	install_requires = [
		line.strip() for line in f if line.strip() and not line.startswith("#")
	]

# get version from __version__ variable in oidc_extended/__init__.py
from oidc_extended import __version__ as version

setup(
	name="oidc_extended",
	version=version,
	description="An extension to the ERPNext Social Login authentication method (OIDC) that incorporates new features designed to meet the needs of enterprises.",
	author="Mohammed Noureldin",
	author_email="contact@mohammednoureldin.com",
	packages=find_packages(exclude=("tests", "tests.*")),
	zip_safe=False,
	include_package_data=True,
	install_requires=install_requires
)
