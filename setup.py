from setuptools import setup, find_packages
import os

FOLDERNAME = "CyvoreOS"

setup(
    name='CyvoreOS',
    #packages=['CyvoreOS', os.path.join(FOLDERNAME, "Plugins"), os.path.join(FOLDERNAME, "Output"), os.path.join(FOLDERNAME, "interfaces")],
    packages=find_packages(),
    package_data={"": [os.path.join(FOLDERNAME, "Resources", "top500urls.txt")]},
    include_package_data=True,
    version='0.1.7.6.3',
    license='MIT',  #https://help.github.com/articles/licensing-a-repository
    description='Next-Gen email threat prevention',
    author='Cyvore',
    author_email='info@cyvore.com',
    url='https://cyvore.com',  # Our website Link
    download_url='https://github.com/cyvore/CyvoreOS/archive/refs/tags/v_0.1.7.6.3.tar.gz',
    keywords=['Anti-Phishing', 'Email-Scanner', 'Optical-Recognition'],
    install_requires=[
        'levenshtein',
        'requests',
        'colorama',
        'future',
        'urlextract',
        'blockcypher',
        'urlexpander',
        'python-whois',
        'eml_parser',
        'python-magic',
        'extract_msg',
        "vt-py"
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3'
    ],
)
