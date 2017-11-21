import codecs
import os
import re

from distutils.core import setup


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
    packages=['webauthn'],
    include_package_data=True,
    version=VERSION,
    description='A WebAuthn Python module.',
    long_description=LONG_DESCRIPTION,
    author='James Barclay',
    author_email='jbarclay@duo.com',
    url='https://github.com/duo-labs/py_webauthn',
    download_url='https://github.com/duo-labs/py_webauthn/archive/'
                 '{}.tar.gz'.format(VERSION),
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python'
    ],
    install_requires=[
        'cbor2>=4.0.1',
        'cryptography>=2.0.3',
        'pyOpenSSL>=16.0.0',
        'six>=1.11.0'
    ]
)
