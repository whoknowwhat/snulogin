from distutils.core import setup

setup(name='snulogin',
      version='0.1.0',
      description='SSO Authentication Module for sso.snu.ac.kr',
      url='https://bitbucket.org/whoknowwhat/snulogin',
      author='eM',
      author_email='whoknowwhat0623@gmail.com',
      packages=['snulogin'],
      requires=['requests(==2.3.0)'],
      zip_safe=False)
