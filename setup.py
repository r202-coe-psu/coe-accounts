import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()
with open(os.path.join(here, 'CHANGES.md')) as f:
    CHANGES = f.read()

requires = [
    'flask',
    'flask-mongoengine',
    'flask-login',
    'flask-allows',
    'authomatic',
    'ldap3',
    'passlib',
    'bcrypt',
   ]

init = os.path.join(os.path.dirname(__file__), 'principal', '__init__.py')
version_line = list(filter(lambda l: l.startswith('__version__'), open(init)))[0]
VERSION = version_line.split('=')[-1].replace('\'', '').strip()

setup(name='principal',
      version=VERSION,
      description='',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
        "Programming Language :: Python",
        "Framework :: Pyramid",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        ],
      author='',
      author_email='',
      url='',
      keywords='',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="principal",
      entry_points="""\
      [console_scripts]
      principal-web = principal.cmd.web:main

      """,
      )
