from distutils.core import setup

setup(
    name='CyvoreOS',
    packages=['CyvoreOS'],
    version='0.1.4',
    license='MIT',  #https://help.github.com/articles/licensing-a-repository
    description='Next-Gen email threat prevention',
    author='Cyvore',
    author_email='info@cyvore.com',
    url='https://github.com/user/reponame',  # Our website Link
    download_url='https://github.com/barakinio/CyvoreOS/archive/refs/tags/v_0.1.1.tar.gz',  # Release Link
    keywords=['Anti-Phishing', 'Email-Scanner', 'Optical-Recognition'],
    install_requires=[
        'levenshtein',
        'requests',
        'favicon',
        'ImageHash',
        'Pillow',
        'urllib3',
        'colorama',
        'future',
        'urlextract'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3'
    ],
)
