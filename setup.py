from distutils.core import setup

setup(name='snulogin',
      version='0.2.0',
      description='SSO Authentication Module for sso.snu.ac.kr',
      url='https://bitbucket.org/whoknowwhat/snulogin',
      author='eM',
      author_email='whoknowwhat0623@gmail.com',
      packages=['snulogin'],
      requires=['requests(>=2.5.3)', 'beautifulsoup4(>=4.3.2)'],
      zip_safe=False)
