from setuptools import setup
import os
import re

setup(name='KeyMe',
      version='0.4.0',
      description='Google SAML STS login library',
      url='http://github.com/wheniwork/keyme',
      author='Richard Genthner',
      author_email='richard.genthner@wheniwork.com',
      packages=['keyme'],
      include_package_data=True,
      install_requires=[
        'Click',
        'boto',
        'bs4',
        'requests',
        'beautifulsoup'
      ],
      scripts=['bin/fetch_creds'],
      license='MIT',
      entry_points = '''
        [console_scripts]
        fetch_creds=fetch_creds:cli
      ''',
      zip_safe=False)
