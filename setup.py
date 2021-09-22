from distutils.core import setup

setup(
    name='CyvoreOS',
    packages=['CyvoreOS'],
    version='0.1',
    license='MIT',  # Chose a license from here: https://help.github.com/articles/licensing-a-repository
    description='TYPE YOUR DESCRIPTION HERE',  # Give a short description about your library
    author='Cyvore',  # Type in your name
    author_email='info@cyvore.com',
    url='https://github.com/user/reponame',  # Provide either the link to your github or to your website
    download_url='https://github.com/barakinio/CyvoreOS/archive/refs/tags/v_01.tar.gz',  # I explain this later on
    keywords=['Anti-Phising', 'Email-Scanner', 'Optical-Recognition'],  # Keywords that define your package best
    install_requires=[
        'alabaster==0.7.12',
        'altgraph==0.17',
        'appdirs==1.4.4',
        'attrs==20.3.0',
        'Automat==20.2.0',
        'Babel==2.9.0',
        'beautifulsoup4==4.9.3',
        'certifi==2020.12.5',
        'cffi==1.14.5',
        'chardet==3.0.4',
        'colorama==0.4.4',
        'constantly==15.1.0',
        'cryptography==3.4.6',
        'cssselect==1.1.0',
        'decorator==4.4.2',
        'docopt==0.6.2',
        'docutils==0.16',
        'filelock==3.0.12',
        'future==0.18.2',
        'huepy==1.2.1',
        'hyperlink==21.0.0',
        'idna==2.10',
        'imagesize==1.2.0',
        'incremental==21.3.0',
        'ipaddress==1.0.23',
        'itemadapter==0.2.0',
        'itemloaders==1.0.4',
        'Jinja2==2.11.2',
        'jmespath==0.10.0',
        'lxml==4.6.2',
        'MarkupSafe==1.1.1',
        'netifaces==0.10.9',
        'ntlm-auth==1.5.0',
        'numpy==1.19.4',
        'packaging==20.7',
        'parsel==1.6.0',
        'pefile==2019.4.18',
        'Pillow==8.1.2',
        'pipreqs==0.4.10',
        'Protego==0.1.16',
        'pyasn1==0.4.8',
        'pyasn1-modules==0.2.8',
        'pycparser==2.20',
        'PyDispatcher==2.0.5',
        'Pygments==2.7.3',
        'pyinstaller==4.1',
        'pyinstaller-hooks-contrib==2020.10',
        'pyOpenSSL==20.0.1',
        'pyparsing==2.4.7',
        'python-nmap==0.6.1',
        'python3-nmap==1.4.8',
        'pytz==2020.4',
        'pywin32==300',
        'pywin32-ctypes==0.2.0',
        'queuelib==1.5.0',
        'requests',
        'requests-ntlm==1.0.0',
        'scapy==2.4.4',
        'Scrapy==2.4.1',
        'selenium==3.141.0',
        'service-identity==18.1.0',
        'simplejson==3.17.2',
        'six==1.15.0',
        'snowballstemmer==2.0.0',
        'soupsieve==2.2',
        'Sphinx==3.3.1',
        'sphinx-rtd-theme==0.5.0',
        'sphinxcontrib-applehelp==1.0.2',
        'sphinxcontrib-devhelp==1.0.2',
        'sphinxcontrib-htmlhelp==1.0.3',
        'sphinxcontrib-jsmath==1.0.1',
        'sphinxcontrib-qthelp==1.0.3',
        'sphinxcontrib-serializinghtml==1.1.4',
        'Twisted==21.2.0',
        'twisted-iocpsupport==1.0.1',
        'uritools==3.0.0',
        'urlextract==1.2.0',
        'urllib3==1.26.2',
        'validators==0.11.3',
        'w3lib==1.22.0',
        'yarg==0.1.9',
        'zope.interface==5.2.0',
        'pytesseract~=0.3.7',
        'opencv-python~=4.5.2.54',
        'favicon~=0.7.0',
        'ImageHash~=4.2.0',
        'nltk~=3.6.2',
        'HTMLParser~=0.0.2',
        'levenshtein~=0.12.0'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',  # Again, pick a license
        'Programming Language :: Python :: 3'
    ],
)
