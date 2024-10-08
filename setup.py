from setuptools import setup, find_packages
import os

FOLDERNAME = "CyvoreOS"

setup(
    name='CyvoreOS',
    #packages=['CyvoreOS', os.path.join(FOLDERNAME, "Plugins"), os.path.join(FOLDERNAME, "Output"), os.path.join(FOLDERNAME, "interfaces")],
    packages=find_packages(),
    package_data={"": [os.path.join(FOLDERNAME, "Resources", "top500urls.txt")]},
    include_package_data=True,
    version='0.2',
    license='MIT',  #https://help.github.com/articles/licensing-a-repository
    description='Next-Gen email threat prevention',
    author='Cyvore',
    author_email='info@cyvore.com',
    url='https://cyvore.com',  # Our website Link
    download_url='https://github.com/cyvore/CyvoreOS/archive/refs/tags/v_0.1.7.6.6.tar.gz',
    keywords=['Anti-Phishing', 'Email-Scanner', 'Optical-Recognition'],
    install_requires=[
        'levenshtein==0.18.1',
        'requests==2.27.1',
        'colorama==0.4.6',
        'future==0.18.2',
        'urlextract==1.5.0',
        'blockcypher==1.0.93',
        'urlexpander==0.0.37',
        'python-whois==0.9.4',
        'eml_parser==1.17.5',
        'python-magic==0.4.27',
        'extract_msg==0.40.0',
        "vt-py==0.14.0"
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3'
    ],
)
