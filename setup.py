from setuptools import setup

setup(
    name='auth_tkt',
    version='0.1.0',
    description='Python implementation of mod_auth_tkt cookies',
    author='Yola',
    license='MIT (Expat)',
    author_email='engineers@yola.com',
    url='http://github.com/yola/auth_tkt',
    packages=['auth_tkt'],
    test_suite='nose.collector',
    install_requires=['cryptography < 2.0.0']
)
