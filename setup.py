from distutils.core import setup
import os

FOLDERNAME = "CyvoreOS"

setup(
    name='CyvoreOS',
    packages=['CyvoreOS', os.path.join(FOLDERNAME, "Plugins"), os.path.join(FOLDERNAME, "Output"), os.path.join(FOLDERNAME, "interfaces")],
    version='0.1.7.3.4',
    license='MIT',  #https://help.github.com/articles/licensing-a-repository
    description='Next-Gen email threat prevention',
    author='Cyvore',
    author_email='info@cyvore.com',
    url='https://github.com/user/reponame',  # Our website Link
    download_url='https://github.com/barakinio/CyvoreOS/archive/refs/tags/v_0.1.7.3.4.tar.gz',
    keywords=['Anti-Phishing', 'Email-Scanner', 'Optical-Recognition'],
    install_requires=[
        'levenshtein',
        'requests',
        'colorama',
        'future',
        'urlextract',
        'blockcypher',
        'urlexpander'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3'
    ],
)
