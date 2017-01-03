import re

from setuptools import setup

with open('auth_tkt/__init__.py') as init_py:
    metadata = dict(re.findall("__([a-z]+)__ = '([^']+)'", init_py.read()))

setup(
    name='auth_tkt',
    version=metadata['version'],
    description=metadata['doc'],
    author='Yola',
    license='MIT (Expat)',
    author_email='engineers@yola.com',
    url='http://github.com/yola/auth_tkt',
    packages=['auth_tkt'],
    test_suite='nose.collector',
    install_requires=['cryptography < 2.0.0']
)
