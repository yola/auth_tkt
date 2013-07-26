from setuptools import setup

setup(
    name='authtkt',
    version='0.0.1',
    description='Python implementation of mod_auth_tkt cookies',
    author='Yola',
    license='MIT (Expat)',
    author_email='engineers@yola.com',
    url='http://github.com/yola/authtkt',
    packages=['authtkt'],
    test_suite='nose.collector',
    install_requires=['M2Crypto < 1.0.0']
)
