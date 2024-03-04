import re

from setuptools import setup

with open('auth_tkt/__init__.py') as init_py:
    metadata = dict(re.findall("__([a-z]+)__ = '([^']+)'", init_py.read()))

with open('README.md', 'r') as readme_file:
    long_description = readme_file.read()

setup(
    name='auth_tkt',
    version=metadata['version'],
    description=metadata['doc'],
    author='Yola',
    author_email='engineers@yola.com',
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='http://github.com/yola/auth_tkt',
    packages=['auth_tkt'],
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    install_requires=['cryptography < 45']
)
