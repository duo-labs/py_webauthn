import codecs
import os
import re

from setuptools import setup, find_packages


HERE = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    with codecs.open(os.path.join(HERE, *parts), 'r') as fp:
        return fp.read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError('Unable to find version string.')


LONG_DESCRIPTION = read('README.md')
VERSION = find_version('webauthn', '__init__.py')


setup(
    name='webauthn',
    packages=find_packages(exclude=["tests"]),
    include_package_data=True,
    version=VERSION,
    description='Pythonic WebAuthn',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    keywords='webauthn fido2',
    author='Duo Labs',
    author_email='labs@duo.com',
    url='https://github.com/duo-labs/py_webauthn',
    download_url='https://github.com/duo-labs/py_webauthn/archive/{}.tar.gz'.format(VERSION),
    license='BSD',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3'
    ],
    install_requires=[
        'asn1crypto>=0.24.0',
        'cbor2>=4.0.1',
        'cryptography>=3.4.7',
        'pydantic>=1.8.2',
        'pyOpenSSL>=20.0.1',
    ]
)
